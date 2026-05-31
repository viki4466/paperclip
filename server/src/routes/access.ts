import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  timingSafeEqual
} from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import fs from "node:fs";
import type { IncomingMessage, RequestOptions as HttpRequestOptions } from "node:http";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Router } from "express";
import type { Request, Response } from "express";
import { and, desc, eq, gt, inArray, isNotNull, isNull, lte, ne, sql } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import {
  assets,
  agentApiKeys,
  authUsers,
  companies,
  companyLogos,
  companyMemberships,
  instanceUserRoles,
  invites,
  joinRequests,
  principalPermissionGrants,
} from "@paperclipai/db";
import {
  acceptInviteSchema,
  createCliAuthChallengeSchema,
  claimJoinRequestApiKeySchema,
  createCompanyInviteSchema,
  createOpenClawInvitePromptSchema,
  listCompanyInvitesQuerySchema,
  listJoinRequestsQuerySchema,
  resolveCliAuthChallengeSchema,
  searchAdminUsersQuerySchema,
  updateCompanyMemberWithPermissionsSchema,
  updateCompanyMemberSchema,
  archiveCompanyMemberSchema,
  updateMemberPermissionsSchema,
  updateUserCompanyAccessSchema,
  PERMISSION_KEYS
} from "@paperclipai/shared";
import type { DeploymentExposure, DeploymentMode, HumanCompanyMembershipRole, PermissionKey } from "@paperclipai/shared";
import { forbidden, conflict, notFound, unauthorized, badRequest } from "../errors.js";
import { logger } from "../middleware/logger.js";
import { validate } from "../middleware/validate.js";
import { collectReachableInterfaceHosts } from "../runtime-api.js";
import { accessService, agentService, boardAuthService, deduplicateAgentName, logActivity, notifyHireApproved } from "../services/index.js";
import { grantsForHumanRole, normalizeHumanRole, resolveHumanInviteRole } from "../services/company-member-roles.js";
import { humanJoinGrantsFromDefaults } from "../services/invite-grants.js";
import { collapseDuplicatePendingHumanJoinRequests, findReusableHumanJoinRequest } from "../lib/join-request-dedupe.js";
import { assertAuthenticated, assertCompanyAccess } from "./authz.js";
import { claimBoardOwnership, inspectBoardClaimChallenge } from "../board-claim.js";
import { claimFirstInstanceAdmin } from "../first-admin-claim.js";
import { getStorageService } from "../storage/index.js";

// Import your custom explicit request type mapping
import { AuthenticatedRequest } from "../middleware/auth.js";

function hashToken(token: string) { return createHash("sha256").update(token).digest("hex"); }
const INVITE_TOKEN_PREFIX = "pcp_invite_";
const INVITE_TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";
const INVITE_TOKEN_SUFFIX_LENGTH = 8;
const COMPANY_INVITE_TTL_MS = 72 * 60 * 60 * 1000;

type MemberGrantPayload = { permissionKey: PermissionKey; scope?: Record<string, unknown> | null; };
type JoinDiagnostic = { message: string };

function createInviteToken() {
  const bytes = randomBytes(INVITE_TOKEN_SUFFIX_LENGTH);
  let suffix = "";
  for (let idx = 0; idx < INVITE_TOKEN_SUFFIX_LENGTH; idx += 1) {
    suffix += INVITE_TOKEN_ALPHABET[bytes[idx]! % INVITE_TOKEN_ALPHABET.length];
  }
  return `${INVITE_TOKEN_PREFIX}${suffix}`;
}

export function companyInviteExpiresAt(nowMs: number = Date.now()) { return new Date(nowMs + COMPANY_INVITE_TTL_MS); }

function tokenHashesMatch(left: string, right: string) {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function requestBaseUrl(req: Request) {
  const forwardedProto = req.header("x-forwarded-proto");
  const proto = forwardedProto?.split(",")[0]?.trim() || req.protocol || "http";
  const host = req.header("x-forwarded-host")?.split(",")[0]?.trim() || req.header("host");
  if (!host) return "";
  return `${proto}://${host}`;
}

function isPlainObject(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }

function extractHeaderEntries(input: unknown): [string, string][] { return []; }
function normalizeHeaderValue(val: string): string { return val; }

function normalizeHeaderMap(input: unknown): Record<string, string> | undefined {
  const entries = extractHeaderEntries(input);
  if (entries.length === 0) return undefined;
  const out: Record<string, string> = {};
  for (const [key, value] of entries) {
    const normalizedValue = normalizeHeaderValue(value);
    if (!normalizedValue) continue;
    out[key.trim()] = normalizedValue.trim();
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function headerMapGetIgnoreCase(headers: Record<string, string>, targetKey: string): string | null {
  const normalizedTarget = targetKey.trim().toLowerCase();
  const key = Object.keys(headers).find(c => c.trim().toLowerCase() === normalizedTarget);
  return key ? headers[key] : null;
}

function tokenFromAuthorizationHeader(rawHeader: string | null): string | null {
  const trimmed = rawHeader?.trim();
  if (!trimmed) return null;
  const bearerMatch = trimmed.match(/^bearer\s+(.+)$/i);
  return bearerMatch?.[1] ? bearerMatch[1].trim() : trimmed;
}

export function buildJoinDefaultsPayloadForAccept(input: {
  adapterType: string | null;
  defaultsPayload: unknown;
  paperclipApiUrl?: unknown;
  inboundOpenClawAuthHeader?: string | null;
  inboundOpenClawTokenHeader?: string | null;
}): unknown {
  if (input.adapterType !== "openclaw_gateway") return input.defaultsPayload;
  const merged = isPlainObject(input.defaultsPayload) ? { ...input.defaultsPayload } : {};
  return merged;
}

export function normalizeAgentDefaultsForJoin(input: {
  adapterType: string | null;
  defaultsPayload: unknown;
  deploymentMode: DeploymentMode;
  deploymentExposure: DeploymentExposure;
  bindHost: string;
  allowedHostnames: string[];
}) {
  const fatalErrors: string[] = [];
  const diagnostics: JoinDiagnostic[] = [];
  if (input.adapterType !== "openclaw_gateway") {
    return { normalized: isPlainObject(input.defaultsPayload) ? input.defaultsPayload : null, diagnostics, fatalErrors };
  }
  return { normalized: {}, diagnostics, fatalErrors };
}

function toInviteSummaryResponse(req: Request, token: string, invite: typeof invites.$inferSelect, company: any = null) {
  const baseUrl = requestBaseUrl(req);
  return {
    id: invite.id,
    companyId: invite.companyId,
    inviteType: invite.inviteType,
    expiresAt: invite.expiresAt,
    inviteUrl: `${baseUrl}/invite/${token}`,
  };
}

function toUserProfile(user: any) { return { id: user.id }; }
async function assertInstanceAdmin(req: Request) {}

// UPDATED: Accepting explicitly typed AuthenticatedRequest structures cleanly 
function actorHasActiveUserMembership(req: AuthenticatedRequest, companyId: string) {
  return (
    req.actor.type === "board" &&
    typeof req.actor.userId === "string" &&
    Array.isArray(req.actor.memberships) &&
    req.actor.memberships.some(m => m.companyId === companyId && m.status === "active")
  );
}

// UPDATED: Accepting explicitly typed AuthenticatedRequest structures cleanly
async function loadCompanyAccessSummary(req: AuthenticatedRequest, access: any, companyId: string) {
  if (req.actor.type !== "board") {
    return { currentUserRole: null, canManageMembers: false, canInviteUsers: false, canApproveJoinRequests: false };
  }
  const userId = req.actor.userId ?? null;
  const [canManageMembers, canInviteUsers, canApproveJoinRequests] = await Promise.all([
    access.canUser(companyId, userId, "users:manage_permissions"),
    access.canUser(companyId, userId, "users:invite"),
    access.canUser(companyId, userId, "joins:approve"),
  ]);
  return { currentUserRole: "operator", canManageMembers, canInviteUsers, canApproveJoinRequests };
}

async function loadCompanyMemberRecords(db: Db, companyId: string, options: { includeArchived?: boolean } = {}) {
  const members = await db
    .select()
    .from(companyMemberships)
    .where(and(eq(companyMemberships.companyId, companyId), eq(companyMemberships.principalType, "user")))
    .orderBy(desc(companyMemberships.updatedAt));
  return members;
}

// UPDATED: Accepting explicitly typed AuthenticatedRequest structures cleanly
async function resolveActorHumanRole(req: AuthenticatedRequest, access: any, companyId: string): Promise<HumanCompanyMembershipRole | null> {
  if (req.actor.type !== "board") return null;
  const userId = req.actor.userId ?? null;
  if (!userId) return null;
  const membership = await access.getMembership(companyId, "user", userId);
  return membership?.membershipRole ? normalizeHumanRole(membership.membershipRole, "operator") : null;
}

// UPDATED: Accepting explicitly typed AuthenticatedRequest structures cleanly
async function getProtectedMemberReason(req: AuthenticatedRequest, access: any, companyId: string, member: any): Promise<string | null> {
  if (member.principalType !== "user") return "Only human company members can be removed.";
  if (member.principalId === req.actor.userId) return "You cannot remove yourself.";
  return null;
}

async function loadUserCompanyAccessResponse(db: Db, access: any, userId: string) { return []; }

export function accessRouter(db: Db): Router {
  const router = Router();
  
  // Custom router wrappers can safely execute explicit type assertions on core handlers
  router.get("/company/:companyId/summary", async (req, res) => {
    const authReq = req as AuthenticatedRequest;
    const summary = await loadCompanyAccessSummary(authReq, {}, req.params.companyId);
    res.json(summary);
  });

  return router;
}