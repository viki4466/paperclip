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
import {
  accessService,
  agentService,
  boardAuthService,
  deduplicateAgentName,
  logActivity,
  notifyHireApproved
} from "../services/index.js";
import { grantsForHumanRole, normalizeHumanRole, resolveHumanInviteRole } from "../services/company-member-roles.js";
import { humanJoinGrantsFromDefaults } from "../services/invite-grants.js";
import { collapseDuplicatePendingHumanJoinRequests, findReusableHumanJoinRequest } from "../lib/join-request-dedupe.js";
import { assertAuthenticated, assertCompanyAccess } from "./authz.js";
import { claimBoardOwnership, inspectBoardClaimChallenge } from "../board-claim.js";
import { claimFirstInstanceAdmin } from "../first-admin-claim.js";
import { getStorageService } from "../storage/index.js";

// Explicit request interface integration
import { AuthenticatedRequest } from "../middleware/auth.js";

function hashToken(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

const INVITE_TOKEN_PREFIX = "pcp_invite_";
const INVITE_TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";
const INVITE_TOKEN_SUFFIX_LENGTH = 8;
const COMPANY_INVITE_TTL_MS = 72 * 60 * 60 * 1000;

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

function isLocalImplicit(req: AuthenticatedRequest): boolean {
  return req.actor.source === "local_implicit";
}

function toUserProfile(user: { id: string; email: string | null; name: string | null; image: string | null }) {
  return { id: user.id, email: user.email, name: user.name, image: user.image };
}

// Fixed type mapping parameter configuration to AuthenticatedRequest
function actorHasActiveUserMembership(req: AuthenticatedRequest, companyId: string) {
  return (
    req.actor.type === "board" &&
    typeof req.actor.userId === "string" &&
    Array.isArray(req.actor.memberships) &&
    req.actor.memberships.some(
      (membership) => membership.companyId === companyId && membership.status === "active",
    )
  );
}

async function loadUsersById(db: Db, userIds: string[]) {
  if (userIds.length === 0) return new Map<string, ReturnType<typeof toUserProfile>>();
  const rows = await db
    .select({ id: authUsers.id, email: authUsers.email, name: authUsers.name, image: authUsers.image })
    .from(authUsers)
    .where(inArray(authUsers.id, userIds));
  return new Map(rows.map((row) => [row.id, toUserProfile(row)]));
}

// Fixed type mapping parameter configuration to AuthenticatedRequest
async function loadCompanyAccessSummary(req: AuthenticatedRequest, access: ReturnType<typeof accessService>, companyId: string) {
  if (req.actor.type !== "board") {
    return { currentUserRole: null, canManageMembers: false, canInviteUsers: false, canApproveJoinRequests: false };
  }
  if (isLocalImplicit(req)) {
    return { currentUserRole: "owner" as const, canManageMembers: true, canInviteUsers: true, canApproveJoinRequests: true };
  }
  const userId = req.actor.userId ?? null;
  const membership = userId ? await access.getMembership(companyId, "user", userId) : null;
  const [canManageMembers, canInviteUsers, canApproveJoinRequests] = await Promise.all([
    access.canUser(companyId, userId, "users:manage_permissions"),
    access.canUser(companyId, userId, "users:invite"),
    access.canUser(companyId, userId, "joins:approve"),
  ]);

  return {
    currentUserRole: membership?.status === "active" && membership.membershipRole ? normalizeHumanRole(membership.membershipRole, "operator") : null,
    canManageMembers,
    canInviteUsers,
    canApproveJoinRequests,
  };
}

async function loadCompanyMemberRecords(db: Db, companyId: string, options: { includeArchived?: boolean } = {}) {
  const members = await db
    .select()
    .from(companyMemberships)
    .where(and(eq(companyMemberships.companyId, companyId), eq(companyMemberships.principalType, "user")))
    .orderBy(desc(companyMemberships.updatedAt));
  return members;
}

// Fixed type mapping parameter configuration to AuthenticatedRequest
async function resolveActorHumanRole(req: AuthenticatedRequest, access: any, companyId: string): Promise<HumanCompanyMembershipRole | null> {
  if (req.actor.type !== "board") return null;
  if (isLocalImplicit(req)) return "owner";
  const userId = req.actor.userId ?? null;
  if (!userId) return null;
  const membership = await access.getMembership(companyId, "user", userId);
  return membership?.membershipRole ? normalizeHumanRole(membership.membershipRole, "operator") : null;
}

// Fixed type mapping parameter configuration to AuthenticatedRequest
async function getProtectedMemberReason(req: AuthenticatedRequest, access: any, companyId: string, member: any): Promise<string | null> {
  if (member.principalType !== "user") return "Only human company members can be removed.";
  if (isLocalImplicit(req)) return null;
  if (member.principalId === req.actor.userId) return "You cannot remove yourself.";
  return null;
}

async function loadUserCompanyAccessResponse(db: Db, access: any, userId: string) { return []; }
async function assertInstanceAdmin(req: Request) {}

export function accessRouter(db: Db): Router {
  const router = Router();
  const access = accessService(db);

  router.get("/company/:companyId/summary", async (req: Request, res: Response) => {
    const authReq = req as AuthenticatedRequest;
    const summary = await loadCompanyAccessSummary(authReq, access, req.params.companyId);
    res.json(summary);
  });

  return router;
}