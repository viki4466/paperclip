import { createHash, timingSafeEqual } from "node:crypto";
import type { Request, RequestHandler } from "express";
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

interface ActorMiddlewareOptions {
  deploymentMode: DeploymentMode;
  resolveSession?: (req: Request) => Promise<BetterAuthSessionResult | null>;
}

export function actorMiddleware(db: Db, opts: ActorMiddlewareOptions): RequestHandler {
  const boardAuth = boardAuthService(db);
  return async (req, _res, next) => {
    req.actor =
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

    const runIdHeader = req.header("x-paperclip-run-id");

    const authHeader = req.header("authorization");
    if (!authHeader?.toLowerCase().startsWith("bearer ")) {
      if (opts.deploymentMode === "authenticated" && opts.resolveSession) {
        const cloudTenantActor = await resolveCloudTenantActor(db, req);
        if (cloudTenantActor) {
          req.actor = {
            ...cloudTenantActor,
            runId: runIdHeader ?? undefined,
          };
          next();
          return;
        }

        let session: BetterAuthSessionResult | null = null;
        try {
          session = await opts.resolveSession(req);
        } catch (err) {
          logger.warn(
            { err, method: req.method, url: req.originalUrl },
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
          req.actor = {
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
  };
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
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-...`;
}