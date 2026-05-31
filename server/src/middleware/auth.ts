import { createHash, timingSafeEqual } from "node:crypto";
import type { Request, RequestHandler, Response, NextFunction } from "express";
import { and, eq, isNull } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import { agentApiKeys, agents, authUsers, companies, companyMemberships, instanceUserRoles } from "@paperclipai/db";
import { verifyLocalAgentJwt } from "../agent-auth-jwt.js";
import type { DeploymentMode } from "@paperclipai/shared";
import type { BetterAuthSessionResult } from "../auth/better-auth.js";
import { logger } from "./logger.js";
import { boardAuthService } from "../services/board-auth.js";

function hashToken(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

export interface PaperclipActor {
  type: "board" | "none" | "agent" | string;
  userId?: string | null;
  userName?: string | null;
  userEmail?: string | null;
  isInstanceAdmin?: boolean;
  source: string;
  runId?: string;
  agentId?: string;
  agentName?: string;
  companyId?: string;
  memberships?: Array<{
    companyId: string;
    membershipRole?: string;
    status: string;
  }>;
}

export interface AuthenticatedRequest extends Request {
  actor: PaperclipActor;
}

interface ActorMiddlewareOptions {
  deploymentMode: DeploymentMode;
  resolveSession?: (req: Request) => Promise<BetterAuthSessionResult | null>;
}

export function actorMiddleware(db: Db, opts: ActorMiddlewareOptions): RequestHandler {
  const boardAuth = boardAuthService(db);
  return async (req: Request, _res: Response, next: NextFunction) => {
    const authReq = req as AuthenticatedRequest;

    authReq.actor =
      opts.deploymentMode === "local_trusted"
        ? {
            type: "board",
            userId: "local-board",
            userName: "Local Board",
            userEmail: null,
            isInstanceAdmin: true,
            source: "local_implicit",
          }
        : { type: "none", source: "none" };

    const runIdHeader = authReq.header("x-paperclip-run-id");

    const authHeader = authReq.header("authorization");
    if (!authHeader?.toLowerCase().startsWith("bearer ")) {
      if (opts.deploymentMode === "authenticated" && opts.resolveSession) {
        const cloudTenantActor = await resolveCloudTenantActor(db, authReq);
        if (cloudTenantActor) {
          authReq.actor = {
            ...cloudTenantActor,
            runId: runIdHeader ?? undefined,
          };
          next();
          return;
        }

        let session: BetterAuthSessionResult | null = null;
        try {
          session = await opts.resolveSession(authReq);
        } catch (err) {
          logger.warn(
            { err, method: authReq.method, url: authReq.originalUrl },
            "Failed to resolve auth session from request headers",
          );
        }
        if (session?.user?.id) {
          const userId = session.user.id;
          const [roleRow, memberships] = await Promise.all([
            db
              .select({ id: instanceUserRoles.id })
              .from(instanceUserRoles)
              .where(and(eq(instanceUserRoles.userId, userId), eq(instanceUserRoles.role, "instance_admin")))
              .then((rows) => rows[0] ?? null),
            db
              .select({
                companyId: companyMemberships.companyId,
                membershipRole: companyMemberships.membershipRole,
                status: companyMemberships.status,
              })
              .from(companyMemberships)
              .where(
                and(
                  eq(companyMemberships.principalType, "user"),
                  eq(companyMemberships.principalId, userId),
                  eq(companyMemberships.status, "active"),
                ),
              ),
          ]);
          authReq.actor = {
            type: "board",
            userId,
            userName: session.user.name,
            userEmail: session.user.email,
            isInstanceAdmin: Boolean(roleRow),
            source: "better_auth_session",
            memberships: memberships.map((m) => ({
              companyId: m.companyId,
              membershipRole: m.membershipRole ?? undefined,
              status: m.status,
            })),
          };
        }
      }
      next();
      return;
    }

    const token = authHeader.substring(7).trim();
    if (!token) {
      next();
      return;
    }

    if (token.startsWith("pcp_agent_")) {
      const tokenHash = hashToken(token);
      const [keyRow] = await db
        .select({
          id: agentApiKeys.id,
          agentId: agentApiKeys.agentId,
          companyId: agentApiKeys.companyId,
        })
        .from(agentApiKeys)
        .where(and(eq(agentApiKeys.tokenHash, tokenHash), isNull(agentApiKeys.archivedAt)))
        .limit(1);

      if (keyRow) {
        const [agentRow] = await db
          .select({ id: agents.id, name: agents.name })
          .from(agents)
          .where(eq(agents.id, keyRow.agentId))
          .limit(1);

        if (agentRow) {
          authReq.actor = {
            type: "agent",
            agentId: agentRow.id,
            agentName: agentRow.name,
            companyId: keyRow.companyId,
            source: "agent_api_key",
            runId: runIdHeader ?? undefined,
          };
        }
      }
      next();
      return;
    }

    try {
      const payload = await verifyLocalAgentJwt(token);
      if (payload) {
        authReq.actor = {
          type: "agent",
          agentId: payload.agentId,
          agentName: payload.agentName,
          companyId: payload.companyId,
          source: "agent_jwt",
          runId: runIdHeader ?? undefined,
        };
      }
    } catch (err) {
      logger.debug({ err }, "Bearer token was not a valid local agent JWT");
    }

    next();
  };
}

async function resolveCloudTenantActor(db: Db, req: AuthenticatedRequest): Promise<PaperclipActor | null> {
  const token = tokenFromAuthorizationHeader(req.header("authorization") ?? null);
  if (!token) return null;

  const expectedKey = process.env.PAPERCLIP_CLOUD_TENANT_SECRET;
  if (!expectedKey || expectedKey.length < 16) return null;

  if (!constantTimeStringEqual(token, expectedKey)) return null;

  const stackId = requiredCloudHeader(req, "x-paperclip-cloud-stack-id");
  const userId = requiredCloudHeader(req, "x-paperclip-cloud-user-id");
  const userName = req.header("x-paperclip-cloud-user-name")?.trim() || "Cloud User";
  const userEmail = req.header("x-paperclip-cloud-user-email")?.trim() || null;
  const stackRole = stackMembershipRole(req.header("x-paperclip-cloud-stack-role"));

  const companyId = cloudTenantCompanyId(stackId);

  return {
    type: "board",
    userId,
    userName,
    userEmail,
    memberships: [
      {
        companyId,
        membershipRole: stackRole,
        status: "active",
      },
    ],
    isInstanceAdmin: true,
    source: "cloud_tenant",
  };
}

function tokenFromAuthorizationHeader(rawHeader: string | null): string | null {
  const trimmed = rawHeader?.trim();
  if (!trimmed) return null;
  const bearerMatch = trimmed.match(/^bearer\s+(.+)$/i);
  return bearerMatch?.[1] ? bearerMatch[1].trim() : trimmed;
}

function requiredCloudHeader(req: Request, name: string): string {
  const value = req.header(name)?.trim();
  if (!value) {
    throw new Error(`Missing trusted Cloud tenant header ${name}`);
  }
  return value;
}

function stackMembershipRole(value: string | undefined): "owner" | "admin" | "member" | "support" {
  if (value === "owner" || value === "admin" || value === "member" || value === "support") {
    return value;
  }
  throw new Error("Invalid trusted Cloud tenant stack role");
}

function constantTimeStringEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function cloudTenantCompanyId(stackId: string): string {
  const bytes = createHash("sha256").update(`paperclip-cloud-tenant-company:${stackId}`).digest();
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.subarray(0, 16).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}