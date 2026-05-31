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

// Concrete type definitions for your Request's Custom Actor object
export interface PaperclipActor {
  type: "board" | "none" | string;
  userId?: string | null;
  userName?: string | null;
  userEmail?: string | null;
  isInstanceAdmin?: boolean;
  source: string;
  runId?: string;
  memberships?: Array<{
    companyId: string;
    membershipRole?: string;
    status: string;
  }>;
}

// Explicit Request Type containing our custom Actor property
export interface AuthenticatedRequest extends Request {
  actor: PaperclipActor;
}

interface ActorMiddlewareOptions {
  deploymentMode: DeploymentMode;
  resolveSession?: (req: Request) => Promise<BetterAuthSessionResult | null>;
}

export function actorMiddleware(db: Db, opts: ActorMiddlewareOptions): RequestHandler {
  const boardAuth = boardAuthService(db);
  
  // Cast RequestHandler parameters to use AuthenticatedRequest explicitly
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
    // Added structural return handling for fallback Next executions
    next();
  };
}

async function resolveCloudTenantActor(db: Db, req: AuthenticatedRequest): Promise<PaperclipActor | null> {
  // Safe mock or cloud resolver fallback schema
  return null;
}