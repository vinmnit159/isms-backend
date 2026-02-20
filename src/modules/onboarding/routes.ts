/**
 * Onboarding Task Routes  –  /api/onboarding
 *
 * Endpoints
 * ─────────
 * GET  /api/onboarding/me           — get or auto-create the calling user's onboarding record
 * POST /api/onboarding/accept-policies  — mark policies accepted (Task 1)
 * POST /api/onboarding/training-start   — record video started      (Task 3)
 * POST /api/onboarding/training-complete — record video finished    (Task 3)
 *
 * Admin-only
 * ──────────
 * GET  /api/onboarding/users         — list all users with their onboarding status (for People page)
 * GET  /api/onboarding/users/:userId — get onboarding detail for one user
 *
 * MDM task (Task 2) is handled automatically:
 *   When the MDM agent successfully checks in, the existing agent/routes.ts writes a
 *   DeviceEnrollment row.  A small helper here reads that to derive the mdm status.
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { prisma } from '../../lib/prisma';
import { authenticate } from '../../lib/auth-middleware';
import { logActivity } from '../../lib/activity-logger';

// ── helpers ──────────────────────────────────────────────────────────────────

const ADMIN_ROLES = ['SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_OWNER'];

/** Ensure a UserOnboarding row exists for the given user; return it. */
async function ensureOnboarding(userId: string, organizationId: string) {
  return prisma.userOnboarding.upsert({
    where: { userId },
    create: { userId, organizationId },
    update: {},
  });
}

/**
 * Derive whether the user has an enrolled (and non-revoked) MDM device.
 * Returns the deviceId (assetId) if enrolled, null otherwise.
 */
async function getMdmStatus(userId: string, organizationId: string): Promise<{ enrolled: boolean; deviceId: string | null; enrolledAt: Date | null }> {
  // Look for assets owned by this user that have a DeviceEnrollment
  const enrollment = await prisma.deviceEnrollment.findFirst({
    where: {
      organizationId,
      revoked: false,
      asset: { ownerId: userId },
    },
    orderBy: { enrolledAt: 'desc' },
    select: { assetId: true, enrolledAt: true },
  });

  return {
    enrolled: !!enrollment,
    deviceId: enrollment?.assetId ?? null,
    enrolledAt: enrollment?.enrolledAt ?? null,
  };
}

/** Build the full task-status object returned to the frontend. */
async function buildStatus(userId: string, organizationId: string) {
  const ob = await ensureOnboarding(userId, organizationId);
  const mdm = await getMdmStatus(userId, organizationId);

  // Sync mdm fields into onboarding row if needed
  if (mdm.enrolled && (!ob.mdmEnrolledAt || !ob.deviceId)) {
    await prisma.userOnboarding.update({
      where: { userId },
      data: {
        mdmEnrolledAt: mdm.enrolledAt,
        deviceId: mdm.deviceId,
      },
    });
    ob.mdmEnrolledAt  = mdm.enrolledAt;
    ob.deviceId       = mdm.deviceId;
  }

  return {
    id: ob.id,
    userId,
    // Task 1
    policyAccepted:        !!ob.policyAcceptedAt,
    policyAcceptedAt:      ob.policyAcceptedAt,
    policyVersionAccepted: ob.policyVersionAccepted,
    // Task 2
    mdmEnrolled:           mdm.enrolled,
    mdmEnrolledAt:         ob.mdmEnrolledAt ?? mdm.enrolledAt,
    deviceId:              ob.deviceId ?? mdm.deviceId,
    // Task 3
    trainingStarted:       !!ob.trainingStartedAt,
    trainingStartedAt:     ob.trainingStartedAt,
    trainingCompleted:     !!ob.trainingCompletedAt,
    trainingCompletedAt:   ob.trainingCompletedAt,
    // Overall
    allComplete:
      !!ob.policyAcceptedAt &&
      mdm.enrolled &&
      !!ob.trainingCompletedAt,
  };
}

// ── Routes ────────────────────────────────────────────────────────────────────

export async function onboardingRoutes(app: FastifyInstance) {

  // ── GET /api/onboarding/me ──────────────────────────────────────────────────
  app.get('/me', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    const userId = user.sub ?? user.id;
    const status = await buildStatus(userId, user.organizationId);
    return reply.send({ success: true, data: status });
  });

  // ── POST /api/onboarding/accept-policies ───────────────────────────────────
  // Body: { policyIds: string[] }  — list of policy ids being accepted
  app.post('/accept-policies', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    const userId = user.sub ?? user.id;
    const { policyIds } = (request.body ?? {}) as { policyIds?: string[] };

    await ensureOnboarding(userId, user.organizationId);

    const updated = await prisma.userOnboarding.update({
      where: { userId },
      data: {
        policyAcceptedAt:      new Date(),
        policyVersionAccepted: JSON.stringify(policyIds ?? []),
      },
    });

    logActivity(userId, 'UPDATED', 'ONBOARDING_POLICY', updated.id);

    const status = await buildStatus(userId, user.organizationId);
    return reply.send({ success: true, data: status });
  });

  // ── POST /api/onboarding/training-start ────────────────────────────────────
  app.post('/training-start', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    const userId = user.sub ?? user.id;

    await ensureOnboarding(userId, user.organizationId);

    // Only set startedAt once
    const existing = await prisma.userOnboarding.findUnique({ where: { userId } });
    if (!existing?.trainingStartedAt) {
      await prisma.userOnboarding.update({
        where: { userId },
        data: { trainingStartedAt: new Date() },
      });
      logActivity(userId, 'UPDATED', 'ONBOARDING_TRAINING_STARTED', userId);
    }

    const status = await buildStatus(userId, user.organizationId);
    return reply.send({ success: true, data: status });
  });

  // ── POST /api/onboarding/training-complete ─────────────────────────────────
  app.post('/training-complete', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const user = (request as any).user;
    const userId = user.sub ?? user.id;

    await ensureOnboarding(userId, user.organizationId);

    const updated = await prisma.userOnboarding.update({
      where: { userId },
      data: {
        trainingStartedAt:   (await prisma.userOnboarding.findUnique({ where: { userId } }))?.trainingStartedAt ?? new Date(),
        trainingCompletedAt: new Date(),
      },
    });

    logActivity(userId, 'UPDATED', 'ONBOARDING_TRAINING_COMPLETE', updated.id);

    const status = await buildStatus(userId, user.organizationId);
    return reply.send({ success: true, data: status });
  });

  // ── GET /api/onboarding/users  (admin only) ────────────────────────────────
  // Returns all org users enriched with onboarding status summary
  app.get('/users', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const requester = (request as any).user;

    if (!ADMIN_ROLES.includes(requester.role)) {
      return reply.status(403).send({ error: 'Forbidden', message: 'Admin access required' });
    }

    const users = await prisma.user.findMany({
      where: { organizationId: requester.organizationId },
      select: {
        id: true, email: true, name: true, role: true, createdAt: true,
        onboarding: true,
      },
      orderBy: { createdAt: 'asc' },
    });

    // For MDM status we need device enrollments per user
    const enrollments = await prisma.deviceEnrollment.findMany({
      where: { organizationId: requester.organizationId, revoked: false },
      select: { assetId: true, enrolledAt: true, asset: { select: { ownerId: true } } },
    });
    const enrolledByUser = new Map<string, { assetId: string; enrolledAt: Date }>();
    for (const e of enrollments) {
      if (e.asset?.ownerId) enrolledByUser.set(e.asset.ownerId, { assetId: e.assetId, enrolledAt: e.enrolledAt });
    }

    const result = users.map(u => {
      const ob = u.onboarding;
      const mdm = enrolledByUser.get(u.id);
      const policyDone   = !!ob?.policyAcceptedAt;
      const mdmDone      = !!mdm;
      const trainingDone = !!ob?.trainingCompletedAt;
      const completedCount = [policyDone, mdmDone, trainingDone].filter(Boolean).length;

      return {
        id:            u.id,
        email:         u.email,
        name:          u.name,
        role:          u.role,
        createdAt:     u.createdAt,
        onboarding: {
          // Task 1
          policyAccepted:        policyDone,
          policyAcceptedAt:      ob?.policyAcceptedAt ?? null,
          policyVersionAccepted: ob?.policyVersionAccepted ?? null,
          // Task 2
          mdmEnrolled:           mdmDone,
          mdmEnrolledAt:         mdm?.enrolledAt ?? ob?.mdmEnrolledAt ?? null,
          deviceId:              mdm?.assetId ?? ob?.deviceId ?? null,
          // Task 3
          trainingStarted:       !!ob?.trainingStartedAt,
          trainingStartedAt:     ob?.trainingStartedAt ?? null,
          trainingCompleted:     trainingDone,
          trainingCompletedAt:   ob?.trainingCompletedAt ?? null,
          // Summary
          completedCount,
          totalCount:    3,
          allComplete:   completedCount === 3,
        },
      };
    });

    return reply.send({ success: true, data: result });
  });

  // ── GET /api/onboarding/users/:userId  (admin only) ───────────────────────
  app.get('/users/:userId', { onRequest: [authenticate] }, async (request: FastifyRequest, reply: FastifyReply) => {
    const requester = (request as any).user;
    const { userId } = request.params as { userId: string };

    if (!ADMIN_ROLES.includes(requester.role)) {
      return reply.status(403).send({ error: 'Forbidden', message: 'Admin access required' });
    }

    const user = await prisma.user.findFirst({
      where: { id: userId, organizationId: requester.organizationId },
      select: { id: true, email: true, name: true, role: true, createdAt: true },
    });
    if (!user) return reply.status(404).send({ error: 'Not found' });

    const status = await buildStatus(userId, requester.organizationId);
    return reply.send({ success: true, data: { user, onboarding: status } });
  });
}
