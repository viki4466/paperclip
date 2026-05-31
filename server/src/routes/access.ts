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
import type { Request } from "express";
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

function hashToken(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

const INVITE_TOKEN_PREFIX = "pcp_invite_";
const INVITE_TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";
const INVITE_TOKEN_SUFFIX_LENGTH = 8;
const INVITE_TOKEN_MAX_RETRIES = 5;
const COMPANY_INVITE_TTL_MS = 72 * 60 * 60 * 1000;
const INVITE_RESOLUTION_DNS_TIMEOUT_MS = 3_000;

function isLocalImplicit(req: Request): boolean {
  return req.actor.source === "local_implicit";
}

function toUserProfile(user: { id: string; email: string | null; name: string | null; image: string | null }) {
  return { id: user.id, email: user.email, name: user.name, image: user.image };
}

function extractInviteMessage(invite: any) {
  return invite.customMessage ?? null;
}

function extractInviteHumanRole(invite: any): HumanCompanyMembershipRole {
  return (invite.humanRole as HumanCompanyMembershipRole) ?? "operator";
}

// Global actor mappings function cleanly here without Type casting
function actorHasActiveUserMembership(req: Request, companyId: string) {
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

async function loadCompanyAccessSummary(req: Request, access: ReturnType<typeof accessService>, companyId: string) {
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

// Additional controller logic and route exports proceed below without changes...