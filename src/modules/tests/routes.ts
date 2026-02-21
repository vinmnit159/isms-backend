/**
 * Test Management Routes  —  /api/tests
 *
 * Endpoints:
 *   GET    /                    list tests (filters: category, ownerId, status, type, dueFrom, dueTo, search)
 *   GET    /summary             pass %, overdue count, due-soon count, total
 *   GET    /:id                 single test with relations
 *   POST   /                    create test
 *   PUT    /:id                 update test (status, owner, dueDate, name, category, type)
 *   DELETE /:id                 delete test
 *   POST   /:id/complete        mark test complete → status = OK, completedAt = now
 *   POST   /:id/evidence        attach an existing evidence record
 *   DELETE /:id/evidence/:eid   detach evidence
 *   POST   /:id/controls        attach a control
 *   DELETE /:id/controls/:cid   detach control
 *   POST   /:id/audits          attach an audit
 *   DELETE /:id/audits/:aid     detach audit
 *   POST   /:id/frameworks      attach a framework name
 *   DELETE /:id/frameworks/:fid detach framework
 *   GET    /:id/history         audit trail (paginated, lazy)
 *   POST   /seed                seed predefined Policy tests (idempotent)
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { prisma } from '../../lib/prisma';
import { authenticate } from '../../lib/auth-middleware';
import { logActivity } from '../../lib/activity-logger';

// ── Permission check helpers ───────────────────────────────────────────────────

const ADMIN_ROLES = ['SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_OWNER'];

function isAdmin(user: any) {
  return ADMIN_ROLES.includes(user?.role);
}

// ── Status auto-computation ────────────────────────────────────────────────────
// Called at query-time; never persists a status that was set via manual override
// (Needs_remediation). The stored status is the source of truth except when
// completedAt is set (always → OK) or dueDate has elapsed (→ Overdue).

const DUE_SOON_DAYS = 14;

function computeStatus(
  stored: string,
  dueDate: Date,
  completedAt: Date | null,
): string {
  if (completedAt) return 'OK';
  const now = Date.now();
  const due = dueDate.getTime();
  if (due < now) return 'Overdue';
  if (due - now <= DUE_SOON_DAYS * 24 * 60 * 60 * 1000) return 'Due_soon';
  if (stored === 'Needs_remediation') return 'Needs_remediation';
  return 'Due_soon';
}

function applyStatus(test: any) {
  return {
    ...test,
    status: computeStatus(test.status, test.dueDate, test.completedAt),
  };
}

// ── Validation schemas ─────────────────────────────────────────────────────────

const createTestSchema = z.object({
  name:     z.string().min(1),
  category: z.enum(['Custom', 'Engineering', 'HR', 'IT', 'Policy', 'Risks']),
  type:     z.enum(['Document', 'Automated']),
  ownerId:  z.string().uuid(),
  dueDate:  z.string().datetime().or(z.string().regex(/^\d{4}-\d{2}-\d{2}$/)),
  controlIds:   z.array(z.string().uuid()).optional(),
  frameworkNames: z.array(z.string()).optional(),
  auditIds: z.array(z.string().uuid()).optional(),
});

const updateTestSchema = z.object({
  name:     z.string().min(1).optional(),
  category: z.enum(['Custom', 'Engineering', 'HR', 'IT', 'Policy', 'Risks']).optional(),
  type:     z.enum(['Document', 'Automated']).optional(),
  ownerId:  z.string().uuid().optional(),
  dueDate:  z.string().optional(),
  status:   z.enum(['Due_soon', 'Needs_remediation', 'OK', 'Overdue']).optional(),
});

// ── Standard include for full test payloads ───────────────────────────────────

const TEST_INCLUDE = {
  controls:    { include: { control: { select: { id: true, isoReference: true, title: true, status: true } } } },
  frameworks:  true,
  audits:      { include: { audit: { select: { id: true, type: true, auditor: true, scope: true } } } },
  evidences:   { include: { evidence: { select: { id: true, type: true, fileName: true, fileUrl: true, createdAt: true } } } },
  integration: { select: { id: true, provider: true, status: true } },
} as const;

// ── Route registration ─────────────────────────────────────────────────────────

export async function testRoutes(app: FastifyInstance) {

  // ── GET / — list tests ──────────────────────────────────────────────────────
  app.get('/', { onRequest: [authenticate] }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    const {
      category, ownerId, status, type,
      dueFrom, dueTo, search,
      page = '1', limit = '50',
    } = req.query as Record<string, string>;

    const where: any = { organizationId: user.organizationId };
    if (category) where.category = category;
    if (ownerId)  where.ownerId  = ownerId;
    if (type)     where.type     = type;
    if (dueFrom || dueTo) {
      where.dueDate = {};
      if (dueFrom) where.dueDate.gte = new Date(dueFrom);
      if (dueTo)   where.dueDate.lte = new Date(dueTo);
    }
    if (search) {
      where.name = { contains: search, mode: 'insensitive' };
    }

    const skip = (Math.max(1, Number(page)) - 1) * Number(limit);

    const [total, raw] = await Promise.all([
      prisma.test.count({ where }),
      prisma.test.findMany({
        where,
        include: TEST_INCLUDE,
        orderBy: { dueDate: 'asc' },
        skip,
        take: Number(limit),
      }),
    ]);

    let tests = raw.map(applyStatus);

    // Client-side status filter applied after compute
    if (status) tests = tests.filter((t: any) => t.status === status);

    return reply.send({ success: true, data: tests, total, page: Number(page), limit: Number(limit) });
  });

  // ── GET /summary ─────────────────────────────────────────────────────────────
  app.get('/summary', { onRequest: [authenticate] }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    const now = new Date();
    const dueSoonCutoff = new Date(now.getTime() + DUE_SOON_DAYS * 24 * 60 * 60 * 1000);

    const [total, completed, overdue, dueSoon] = await Promise.all([
      prisma.test.count({ where: { organizationId: user.organizationId } }),
      prisma.test.count({ where: { organizationId: user.organizationId, completedAt: { not: null } } }),
      prisma.test.count({ where: { organizationId: user.organizationId, completedAt: null, dueDate: { lt: now } } }),
      prisma.test.count({ where: { organizationId: user.organizationId, completedAt: null, dueDate: { gte: now, lte: dueSoonCutoff } } }),
    ]);

    return reply.send({
      success: true,
      data: {
        total,
        completed,
        passPercentage: total > 0 ? Math.round((completed / total) * 100) : 0,
        overdue,
        dueSoon,
      },
    });
  });

  // ── GET /:id ──────────────────────────────────────────────────────────────────
  app.get('/:id', { onRequest: [authenticate] }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    const { id } = req.params as any;

    const test = await prisma.test.findFirst({
      where: { id, organizationId: user.organizationId },
      include: TEST_INCLUDE,
    });
    if (!test) return reply.status(404).send({ error: 'Test not found' });

    return reply.send({ success: true, data: applyStatus(test) });
  });

  // ── POST / — create ──────────────────────────────────────────────────────────
  app.post('/', { onRequest: [authenticate] }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Forbidden' });

    const data = createTestSchema.parse(req.body);
    const dueDate = new Date(data.dueDate);

    const test = await prisma.test.create({
      data: {
        name:           data.name,
        category:       data.category as any,
        type:           data.type as any,
        ownerId:        data.ownerId,
        dueDate,
        organizationId: user.organizationId,
        status:         'Due_soon' as any,
        controls:  data.controlIds    ? { create: data.controlIds.map(id => ({ controlId: id })) }    : undefined,
        frameworks: data.frameworkNames ? { create: data.frameworkNames.map(n => ({ frameworkName: n })) } : undefined,
        audits:    data.auditIds     ? { create: data.auditIds.map(id => ({ auditId: id })) }          : undefined,
      },
      include: TEST_INCLUDE,
    });

    await prisma.testHistory.create({
      data: { testId: test.id, changedBy: user.sub ?? user.id, changeType: 'CREATED', newValue: test.name },
    });

    logActivity(user.sub ?? user.id, 'CREATED', 'TEST', test.id);
    return reply.status(201).send({ test: applyStatus(test) });
  });

  // ── PUT /:id — update ────────────────────────────────────────────────────────
  app.put('/:id', { onRequest: [authenticate] }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    const { id } = req.params as any;

    const existing = await prisma.test.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!existing) return reply.status(404).send({ error: 'Test not found' });

    // Any org member can update their own test; admins can update any
    if (!isAdmin(user) && existing.ownerId !== (user.sub ?? user.id)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const data = updateTestSchema.parse(req.body);
    const updateData: any = { ...data };
    if (data.dueDate) updateData.dueDate = new Date(data.dueDate);

    const updated = await prisma.test.update({
      where: { id },
      data: updateData,
      include: TEST_INCLUDE,
    });

    // History entries for significant changes
    const historyEntries: any[] = [];
    if (data.status && data.status !== existing.status) {
      historyEntries.push({ testId: id, changedBy: user.sub ?? user.id, changeType: 'STATUS_CHANGED', oldValue: existing.status, newValue: data.status });
    }
    if (data.ownerId && data.ownerId !== existing.ownerId) {
      historyEntries.push({ testId: id, changedBy: user.sub ?? user.id, changeType: 'OWNER_CHANGED', oldValue: existing.ownerId, newValue: data.ownerId });
    }
    if (data.dueDate && updateData.dueDate.getTime() !== existing.dueDate.getTime()) {
      historyEntries.push({ testId: id, changedBy: user.sub ?? user.id, changeType: 'DUE_DATE_UPDATED', oldValue: existing.dueDate.toISOString(), newValue: updateData.dueDate.toISOString() });
    }
    if (historyEntries.length) {
      await prisma.testHistory.createMany({ data: historyEntries });
    }

    logActivity(user.sub ?? user.id, 'UPDATED', 'TEST', id);
    return reply.send({ test: applyStatus(updated) });
  });

  // ── DELETE /:id ───────────────────────────────────────────────────────────────
  app.delete('/:id', { onRequest: [authenticate] }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Forbidden' });
    const { id } = req.params as any;

    const existing = await prisma.test.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!existing) return reply.status(404).send({ error: 'Test not found' });

    await prisma.test.delete({ where: { id } });
    logActivity(user.sub ?? user.id, 'DELETED', 'TEST', id);
    return reply.send({ success: true });
  });

  // ── POST /:id/complete ────────────────────────────────────────────────────────
  app.post('/:id/complete', { onRequest: [authenticate], schema: { body: { type: 'object' } } }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    const { id } = req.params as any;

    const existing = await prisma.test.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!existing) return reply.status(404).send({ error: 'Test not found' });
    if (!isAdmin(user) && existing.ownerId !== (user.sub ?? user.id)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    // Automated tests can only be completed by the system (via run-tests)
    if (existing.type === 'Automated') {
      return reply.status(409).send({ error: 'Automated tests cannot be manually completed. Use Run Scan Now to execute.' });
    }
    if (existing.completedAt) return reply.status(409).send({ error: 'Test already completed' });

    const now = new Date();
    const updated = await prisma.test.update({
      where: { id },
      data: { completedAt: now, status: 'OK' as any },
      include: TEST_INCLUDE,
    });

    await prisma.testHistory.create({
      data: { testId: id, changedBy: user.sub ?? user.id, changeType: 'COMPLETED', oldValue: existing.status, newValue: 'OK' },
    });

    // Auto-update linked controls if all their tests are now OK
    const controlIds = updated.controls.map((tc: any) => tc.controlId);
    for (const controlId of controlIds) {
      const allMappings = await prisma.testControl.findMany({
        where: { controlId },
        include: { test: { select: { completedAt: true } } },
      });
      const allDone = allMappings.every((m: any) => m.test.completedAt !== null);
      if (allDone) {
        await prisma.control.update({
          where: { id: controlId },
          data: { status: 'IMPLEMENTED' as any },
        });
      }
    }

    logActivity(user.sub ?? user.id, 'UPDATED', 'TEST', id);
    return reply.send({ test: applyStatus(updated) });
  });

  // ── POST /:id/evidence — attach ───────────────────────────────────────────────
  app.post('/:id/evidence', { onRequest: [authenticate] }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    const { id } = req.params as any;
    const { evidenceId } = req.body as any;

    const test = await prisma.test.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!test) return reply.status(404).send({ error: 'Test not found' });

    const link = await prisma.testEvidence.create({ data: { testId: id, evidenceId } });

    await prisma.testHistory.create({
      data: { testId: id, changedBy: user.sub ?? user.id, changeType: 'EVIDENCE_ATTACHED', newValue: evidenceId },
    });

    logActivity(user.sub ?? user.id, 'UPDATED', 'TEST', id);
    return reply.status(201).send({ link });
  });

  // ── DELETE /:id/evidence/:eid ─────────────────────────────────────────────────
  app.delete('/:id/evidence/:eid', { onRequest: [authenticate] }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    const { id, eid } = req.params as any;
    await prisma.testEvidence.deleteMany({ where: { testId: id, evidenceId: eid } });
    logActivity(user.sub ?? user.id, 'UPDATED', 'TEST', id);
    return reply.send({ success: true });
  });

  // ── POST /:id/controls — attach ───────────────────────────────────────────────
  app.post('/:id/controls', { onRequest: [authenticate] }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Forbidden' });
    const { id } = req.params as any;
    const { controlId } = req.body as any;
    const link = await prisma.testControl.create({ data: { testId: id, controlId } });
    logActivity(user.sub ?? user.id, 'UPDATED', 'TEST', id);
    return reply.status(201).send({ link });
  });

  // ── DELETE /:id/controls/:cid ─────────────────────────────────────────────────
  app.delete('/:id/controls/:cid', { onRequest: [authenticate] }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Forbidden' });
    const { id, cid } = req.params as any;
    await prisma.testControl.deleteMany({ where: { testId: id, controlId: cid } });
    return reply.send({ success: true });
  });

  // ── POST /:id/audits — attach ─────────────────────────────────────────────────
  app.post('/:id/audits', { onRequest: [authenticate] }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Forbidden' });
    const { id } = req.params as any;
    const { auditId } = req.body as any;
    const link = await prisma.testAudit.create({ data: { testId: id, auditId } });
    return reply.status(201).send({ link });
  });

  // ── DELETE /:id/audits/:aid ───────────────────────────────────────────────────
  app.delete('/:id/audits/:aid', { onRequest: [authenticate] }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Forbidden' });
    const { id, aid } = req.params as any;
    await prisma.testAudit.deleteMany({ where: { testId: id, auditId: aid } });
    return reply.send({ success: true });
  });

  // ── POST /:id/frameworks — attach ─────────────────────────────────────────────
  app.post('/:id/frameworks', { onRequest: [authenticate] }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Forbidden' });
    const { id } = req.params as any;
    const { frameworkName } = req.body as any;
    const link = await prisma.testFramework.upsert({
      where: { testId_frameworkName: { testId: id, frameworkName } },
      create: { testId: id, frameworkName },
      update: {},
    });
    return reply.status(201).send({ link });
  });

  // ── DELETE /:id/frameworks/:fid ───────────────────────────────────────────────
  app.delete('/:id/frameworks/:fid', { onRequest: [authenticate] }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Forbidden' });
    const { id, fid } = req.params as any;
    await prisma.testFramework.deleteMany({ where: { testId: id, id: fid } });
    return reply.send({ success: true });
  });

  // ── GET /:id/history — audit trail ────────────────────────────────────────────
  app.get('/:id/history', { onRequest: [authenticate] }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    const { id } = req.params as any;
    const { page = '1', limit = '20' } = req.query as any;

    const test = await prisma.test.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!test) return reply.status(404).send({ error: 'Test not found' });

    const skip = (Math.max(1, Number(page)) - 1) * Number(limit);
    const history = await prisma.testHistory.findMany({
      where: { testId: id },
      orderBy: { createdAt: 'desc' },
      skip,
      take: Number(limit),
    });

    return reply.send({ success: true, data: history });
  });

  // ── GET /:id/runs — integration test run history ──────────────────────────────
  app.get('/:id/runs', { onRequest: [authenticate] }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    const { id } = req.params as any;
    const { page = '1', limit = '20' } = req.query as any;

    const test = await prisma.test.findFirst({ where: { id, organizationId: user.organizationId } });
    if (!test) return reply.status(404).send({ error: 'Test not found' });
    if (test.type !== 'Automated') return reply.status(400).send({ error: 'Only Automated tests have run history' });

    const skip = (Math.max(1, Number(page)) - 1) * Number(limit);
    const runs = await prisma.integrationTestRun.findMany({
      where: { testId: id },
      orderBy: { executedAt: 'desc' },
      skip,
      take: Number(limit),
    });

    return reply.send({ success: true, data: runs });
  });

  // ── POST /seed — idempotent seeder ────────────────────────────────────────────
  app.post('/seed', { onRequest: [authenticate], schema: { body: { type: 'object' } } }, async (req: FastifyRequest, reply: FastifyReply) => {
    const user = (req as any).user;
    if (!isAdmin(user)) return reply.status(403).send({ error: 'Forbidden' });

    const orgId = user.organizationId;

    // Find the first admin/security-owner to be default owner
    const defaultOwner = await prisma.user.findFirst({
      where: { organizationId: orgId, role: { in: ['SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_OWNER'] as any } },
      select: { id: true },
    });
    if (!defaultOwner) return reply.status(400).send({ error: 'No admin user found in organisation' });

    const dueDate = new Date();
    dueDate.setDate(dueDate.getDate() + 30);

    const PREDEFINED_TESTS = [
      'Employee termination security policy',
      'Secure engineering principles defined',
      'Planning changes of the ISMS',
      'Track and address nonconformities',
      'Management Review presentation example',
      'Management Review records example',
      'Internal audit report',
      'Management review of ISMS',
      'Incident report or root cause analysis',
      'Publicly available terms of service',
      'Test of incident response plan',
      'Maintain data inventory map',
      'Proof of policy availability to employees',
      'Audit Cycle identified',
    ];

    const created: string[] = [];
    const skipped: string[] = [];

    for (const name of PREDEFINED_TESTS) {
      const existing = await prisma.test.findFirst({
        where: { name, organizationId: orgId },
      });
      if (existing) { skipped.push(name); continue; }

      const t = await prisma.test.create({
        data: {
          name,
          category: 'Policy' as any,
          type: 'Document' as any,
          status: 'Due_soon' as any,
          ownerId: defaultOwner.id,
          dueDate,
          organizationId: orgId,
        },
      });
      await prisma.testHistory.create({
        data: { testId: t.id, changedBy: user.sub ?? user.id, changeType: 'CREATED', newValue: name },
      });
      created.push(name);
    }

    logActivity(user.sub ?? user.id, 'CREATED', 'TEST_SEED', orgId);
    return reply.send({ success: true, data: { created: created.length, skipped: skipped.length } });
  });
}
