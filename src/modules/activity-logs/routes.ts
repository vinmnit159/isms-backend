import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { prisma } from '../../lib/prisma';
import { requirePermission, Permission } from '../../lib/rbac';

/**
 * Human-readable labels for activity log entries shown in the UI.
 * Combines action + entity into a friendly sentence.
 */
function buildLabel(action: string, entity: string, entityName?: string): string {
  const entityLabel = entityName
    ? `"${entityName}"`
    : entity.charAt(0) + entity.slice(1).toLowerCase();

  switch (action) {
    case 'CREATED':    return `${entity.charAt(0) + entity.slice(1).toLowerCase()} created: ${entityLabel}`;
    case 'UPDATED':    return `${entity.charAt(0) + entity.slice(1).toLowerCase()} updated: ${entityLabel}`;
    case 'DELETED':    return `${entity.charAt(0) + entity.slice(1).toLowerCase()} deleted`;
    case 'UPLOADED':   return `File uploaded for ${entity.toLowerCase()}: ${entityLabel}`;
    case 'SCANNED':    return `GitHub scan completed`;
    case 'CONNECTED':  return `GitHub integration connected`;
    case 'DISCONNECTED': return `GitHub integration disconnected`;
    case 'SYSTEM_SETUP': return `System setup completed`;
    default:           return `${action} on ${entity.toLowerCase()}`;
  }
}

/**
 * Maps action → status for dot colour in the UI.
 *  success  → green
 *  warning  → orange
 *  info     → blue
 */
function actionStatus(action: string): 'success' | 'warning' | 'info' {
  if (['CREATED', 'CONNECTED', 'SCANNED', 'SYSTEM_SETUP', 'UPLOADED'].includes(action)) return 'success';
  if (['DELETED', 'DISCONNECTED'].includes(action)) return 'warning';
  return 'info';
}

/** Relative time string, e.g. "3 minutes ago" */
function timeAgo(date: Date): string {
  const diff = Date.now() - date.getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)  return 'just now';
  if (m < 60) return `${m} minute${m !== 1 ? 's' : ''} ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} hour${h !== 1 ? 's' : ''} ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d} day${d !== 1 ? 's' : ''} ago`;
  const mo = Math.floor(d / 30);
  return `${mo} month${mo !== 1 ? 's' : ''} ago`;
}

export async function activityLogRoutes(app: FastifyInstance) {
  /**
   * GET /api/activity-logs
   * Returns the 15 most recent activity log entries for the current user's
   * organisation, enriched with human-readable labels for the home page feed.
   *
   * Query params:
   *   limit  — max records to return (default 15, max 50)
   */
  app.get(
    '/',
    { onRequest: [requirePermission(Permission.READ_CONTROLS)] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const user = request.user as any;
        const { limit: limitParam } = request.query as { limit?: string };
        const limit = Math.min(Number(limitParam) || 15, 50);

        // ActivityLog has no organizationId — filter via user's org
        // Get all user IDs that belong to this org, then query logs for those users
        const orgUsers = await prisma.user.findMany({
          where: { organizationId: user.organizationId },
          select: { id: true, name: true, email: true },
        });

        const userMap: Record<string, { name: string; email: string }> = {};
        orgUsers.forEach((u) => { userMap[u.id] = { name: u.name ?? u.email, email: u.email }; });
        const orgUserIds = orgUsers.map((u) => u.id);

        const logs = await prisma.activityLog.findMany({
          where: { userId: { in: orgUserIds } },
          orderBy: { timestamp: 'desc' },
          take: limit,
          include: {
            user: { select: { name: true, email: true } },
          },
        });

        // Try to resolve a human-friendly entity name for certain entity types
        const enriched = await Promise.all(
          logs.map(async (log) => {
            let entityName: string | undefined;
            try {
              if (log.entity === 'RISK') {
                const r = await prisma.risk.findUnique({ where: { id: log.entityId }, select: { title: true } });
                entityName = r?.title;
              } else if (log.entity === 'ASSET') {
                const a = await prisma.asset.findUnique({ where: { id: log.entityId }, select: { name: true } });
                entityName = a?.name;
              } else if (log.entity === 'POLICY') {
                const p = await prisma.policy.findUnique({ where: { id: log.entityId }, select: { name: true } });
                entityName = p?.name;
              } else if (log.entity === 'EVIDENCE') {
                const e = await prisma.evidence.findUnique({ where: { id: log.entityId }, select: { fileName: true } });
                entityName = e?.fileName ?? undefined;
              } else if (log.entity === 'CONTROL') {
                const c = await prisma.control.findUnique({ where: { id: log.entityId }, select: { title: true } });
                entityName = c?.title;
              }
            } catch {
              // entity may have been deleted — skip name lookup
            }

            return {
              id: log.id,
              action: log.action,
              entity: log.entity,
              entityId: log.entityId,
              entityName,
              label: buildLabel(log.action, log.entity, entityName),
              status: actionStatus(log.action),
              timeAgo: timeAgo(log.timestamp),
              timestamp: log.timestamp,
              user: {
                name: log.user.name,
                email: log.user.email,
              },
            };
          })
        );

        return reply.send({ success: true, data: enriched });
      } catch (err) {
        app.log.error(err);
        return reply.status(500).send({ success: false, error: 'Failed to fetch activity logs' });
      }
    }
  );
}
