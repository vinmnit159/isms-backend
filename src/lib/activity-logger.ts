/**
 * Utility to write to the ActivityLog table.
 * Fire-and-forget — errors are swallowed so they never break a request.
 *
 * Usage:
 *   logActivity(userId, 'CREATED', 'RISK', risk.id, { title: risk.title });
 */

import { prisma } from './prisma';

export type ActivityAction =
  | 'CREATED'
  | 'UPDATED'
  | 'DELETED'
  | 'UPLOADED'
  | 'SCANNED'
  | 'CONNECTED'
  | 'DISCONNECTED'
  | 'SYSTEM_SETUP';

export async function logActivity(
  userId: string,
  action: ActivityAction,
  entity: string,
  entityId: string,
): Promise<void> {
  try {
    await prisma.activityLog.create({
      data: { userId, action, entity, entityId },
    });
  } catch {
    // Never throw — logging failures must not break the main request
  }
}
