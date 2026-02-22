import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { prisma } from '../../lib/prisma';
import { authenticate } from '../../lib/auth-middleware';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function startOf(date: Date): Date {
  const d = new Date(date);
  d.setHours(0, 0, 0, 0);
  return d;
}

/** Buckets a date range into monthly intervals */
function monthBuckets(start: Date, end: Date): Array<{ label: string; from: Date; to: Date }> {
  const buckets: Array<{ label: string; from: Date; to: Date }> = [];
  const cur = new Date(start.getFullYear(), start.getMonth(), 1);
  while (cur <= end) {
    const from = new Date(cur);
    const to = new Date(cur.getFullYear(), cur.getMonth() + 1, 0, 23, 59, 59, 999);
    buckets.push({
      label: from.toLocaleString('en-US', { month: 'short', year: 'numeric' }),
      from,
      to: to > end ? end : to,
    });
    cur.setMonth(cur.getMonth() + 1);
  }
  return buckets;
}

/** Buckets a date range into weekly intervals */
function weekBuckets(start: Date, end: Date): Array<{ label: string; from: Date; to: Date }> {
  const buckets: Array<{ label: string; from: Date; to: Date }> = [];
  const cur = new Date(start);
  // Align to Monday
  const day = cur.getDay();
  cur.setDate(cur.getDate() - ((day + 6) % 7));
  cur.setHours(0, 0, 0, 0);
  while (cur <= end) {
    const from = new Date(cur);
    const to = new Date(cur);
    to.setDate(to.getDate() + 6);
    to.setHours(23, 59, 59, 999);
    buckets.push({
      label: `${from.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}`,
      from,
      to: to > end ? end : to,
    });
    cur.setDate(cur.getDate() + 7);
  }
  return buckets;
}

// ─── Route registration ───────────────────────────────────────────────────────

export async function reportRoutes(fastify: FastifyInstance) {

  // ── GET /api/reports/framework-progress?startDate=&endDate= ──────────────────
  // Returns: per-bucket % of controls in IMPLEMENTED status
  fastify.get(
    '/framework-progress',
    { onRequest: [authenticate] },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const user = (req as any).user;
      const { startDate, endDate, granularity = 'month' } = req.query as Record<string, string>;

      const start = startDate ? new Date(startDate) : new Date(Date.now() - 90 * 86400000);
      const end   = endDate   ? new Date(endDate)   : new Date();

      const allControls = await prisma.control.findMany({
        where: { organizationId: user.organizationId },
        select: { id: true, status: true, createdAt: true },
      });

      const total = allControls.length;
      const buckets = granularity === 'week' ? weekBuckets(start, end) : monthBuckets(start, end);

      // For each bucket, count controls that were IMPLEMENTED as of bucket end
      // We approximate with: controls created before bucket.to + status snapshot
      // Since we don't have history, we return current status against time axis
      const series = buckets.map(b => {
        const implemented = allControls.filter(c => c.status === 'IMPLEMENTED').length;
        return {
          label: b.label,
          implemented,
          total,
          pct: total > 0 ? Math.round((implemented / total) * 100) : 0,
        };
      });

      // Summary
      const implemented = allControls.filter(c => c.status === 'IMPLEMENTED').length;
      const partial     = allControls.filter(c => c.status === 'PARTIALLY_IMPLEMENTED').length;
      const notImpl     = allControls.filter(c => c.status === 'NOT_IMPLEMENTED').length;

      return reply.send({
        success: true,
        data: {
          summary: { total, implemented, partial, notImpl, pct: total > 0 ? Math.round((implemented / total) * 100) : 0 },
          series,
        },
      });
    }
  );

  // ── GET /api/reports/risk-trend?startDate=&endDate= ──────────────────────────
  // Returns: risk counts by severity over time buckets
  fastify.get(
    '/risk-trend',
    { onRequest: [authenticate] },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const user = (req as any).user;
      const { startDate, endDate, granularity = 'month' } = req.query as Record<string, string>;

      const start = startDate ? new Date(startDate) : new Date(Date.now() - 90 * 86400000);
      const end   = endDate   ? new Date(endDate)   : new Date();

      const risks = await prisma.risk.findMany({
        where: {
          asset: { organizationId: user.organizationId },
          createdAt: { gte: start, lte: end },
        },
        select: { id: true, impact: true, status: true, createdAt: true },
      });

      const buckets = granularity === 'week' ? weekBuckets(start, end) : monthBuckets(start, end);

      const series = buckets.map(b => {
        const inBucket = risks.filter(r => r.createdAt >= b.from && r.createdAt <= b.to);
        return {
          label: b.label,
          CRITICAL: inBucket.filter(r => r.impact === 'CRITICAL').length,
          HIGH:     inBucket.filter(r => r.impact === 'HIGH').length,
          MEDIUM:   inBucket.filter(r => r.impact === 'MEDIUM').length,
          LOW:      inBucket.filter(r => r.impact === 'LOW').length,
          total:    inBucket.length,
        };
      });

      // All risks in org for summary
      const allRisks = await prisma.risk.findMany({
        where: { asset: { organizationId: user.organizationId } },
        select: { impact: true, status: true },
      });

      const summary = {
        total:    allRisks.length,
        open:     allRisks.filter(r => r.status === 'OPEN').length,
        mitigated: allRisks.filter(r => r.status === 'MITIGATED').length,
        CRITICAL: allRisks.filter(r => r.impact === 'CRITICAL').length,
        HIGH:     allRisks.filter(r => r.impact === 'HIGH').length,
        MEDIUM:   allRisks.filter(r => r.impact === 'MEDIUM').length,
        LOW:      allRisks.filter(r => r.impact === 'LOW').length,
      };

      return reply.send({ success: true, data: { summary, series } });
    }
  );

  // ── GET /api/reports/test-completion?startDate=&endDate= ────────────────────
  // Returns: test counts bucketed by completion timing category
  fastify.get(
    '/test-completion',
    { onRequest: [authenticate] },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const user = (req as any).user;
      const { startDate, endDate, granularity = 'month' } = req.query as Record<string, string>;

      const start = startDate ? new Date(startDate) : new Date(Date.now() - 90 * 86400000);
      const end   = endDate   ? new Date(endDate)   : new Date();

      const tests = await prisma.test.findMany({
        where: { organizationId: user.organizationId },
        select: { id: true, dueDate: true, completedAt: true, status: true, createdAt: true },
      });

      const buckets = granularity === 'week' ? weekBuckets(start, end) : monthBuckets(start, end);

      const series = buckets.map(b => {
        // Tests completed within this bucket's time window
        const completed = tests.filter(t =>
          t.completedAt && t.completedAt >= b.from && t.completedAt <= b.to
        );
        const onTime    = completed.filter(t => t.completedAt! <= t.dueDate).length;
        const late      = completed.filter(t => t.completedAt! > t.dueDate).length;
        const noDue     = completed.filter(t => !t.dueDate).length;
        return { label: b.label, onTime, late, noDue, total: completed.length };
      });

      const allTests = tests;
      const completed = allTests.filter(t => t.status === 'OK').length;
      const overdue   = allTests.filter(t => t.status === 'Overdue').length;
      const passRate  = allTests.length > 0 ? Math.round((completed / allTests.length) * 100) : 0;

      return reply.send({
        success: true,
        data: {
          summary: { total: allTests.length, completed, overdue, passRate },
          series,
        },
      });
    }
  );

  // ── GET /api/reports/audit-summary?startDate=&endDate= ──────────────────────
  // Returns: audit KPIs + audit list with findings counts
  fastify.get(
    '/audit-summary',
    { onRequest: [authenticate] },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const user = (req as any).user;
      const { startDate, endDate } = req.query as Record<string, string>;

      const start = startDate ? new Date(startDate) : new Date(Date.now() - 90 * 86400000);
      const end   = endDate   ? new Date(endDate)   : new Date();

      const audits = await prisma.audit.findMany({
        where: {
          organizationId: user.organizationId,
          startDate: { gte: start },
        },
        include: { findings: true },
        orderBy: { startDate: 'desc' },
      });

      const completed  = audits.filter(a => a.endDate && a.endDate <= end);
      const inProgress = audits.filter(a => !a.endDate || a.endDate > end);

      const allFindings = audits.flatMap(a => a.findings);
      const openFindings   = allFindings.filter(f => f.status === 'OPEN').length;
      const closedFindings = allFindings.filter(f => f.status === 'CLOSED').length;

      const auditRows = audits.map(a => ({
        id:         a.id,
        type:       a.type,
        auditor:    a.auditor,
        scope:      a.scope,
        startDate:  a.startDate,
        endDate:    a.endDate,
        status:     a.endDate && a.endDate <= new Date() ? 'Completed' : 'In Progress',
        major:      a.findings.filter(f => f.severity === 'MAJOR').length,
        minor:      a.findings.filter(f => f.severity === 'MINOR').length,
        observation: a.findings.filter(f => f.severity === 'OBSERVATION').length,
      }));

      return reply.send({
        success: true,
        data: {
          summary: {
            totalAudits:    audits.length,
            completed:      completed.length,
            inProgress:     inProgress.length,
            openFindings,
            closedFindings,
          },
          audits: auditRows,
        },
      });
    }
  );

  // ── GET /api/reports/evidence-coverage ───────────────────────────────────────
  // Returns: per-control evidence count
  fastify.get(
    '/evidence-coverage',
    { onRequest: [authenticate] },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const user = (req as any).user;

      const controls = await prisma.control.findMany({
        where: { organizationId: user.organizationId },
        include: { evidence: true },
        orderBy: { isoReference: 'asc' },
      });

      const withEvidence    = controls.filter(c => c.evidence.length > 0).length;
      const withoutEvidence = controls.filter(c => c.evidence.length === 0).length;
      const coveragePct     = controls.length > 0
        ? Math.round((withEvidence / controls.length) * 100)
        : 0;

      return reply.send({
        success: true,
        data: {
          summary: {
            total: controls.length,
            withEvidence,
            withoutEvidence,
            coveragePct,
          },
          controls: controls.map(c => ({
            id:           c.id,
            isoReference: c.isoReference,
            title:        c.title,
            status:       c.status,
            evidenceCount: c.evidence.length,
          })),
        },
      });
    }
  );

  // ── GET /api/reports/personnel-compliance ────────────────────────────────────
  // Returns: per-user onboarding completion status
  fastify.get(
    '/personnel-compliance',
    { onRequest: [authenticate] },
    async (req: FastifyRequest, reply: FastifyReply) => {
      const user = (req as any).user;

      const users = await prisma.user.findMany({
        where: { organizationId: user.organizationId },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          createdAt: true,
          onboarding: {
            select: {
              policyAcceptedAt: true,
              mdmEnrolledAt: true,
              trainingCompletedAt: true,
            },
          },
        },
        orderBy: { createdAt: 'asc' },
      });

      const rows = users.map(u => {
        const ob = u.onboarding;
        const done = [ob?.policyAcceptedAt, ob?.mdmEnrolledAt, ob?.trainingCompletedAt].filter(Boolean).length;
        return {
          id:       u.id,
          name:     u.name ?? u.email,
          email:    u.email,
          role:     u.role,
          policyAccepted:     !!ob?.policyAcceptedAt,
          mdmEnrolled:        !!ob?.mdmEnrolledAt,
          trainingCompleted:  !!ob?.trainingCompletedAt,
          completedCount:     done,
          allComplete:        done === 3,
        };
      });

      const allComplete   = rows.filter(r => r.allComplete).length;
      const partial       = rows.filter(r => r.completedCount > 0 && !r.allComplete).length;
      const notStarted    = rows.filter(r => r.completedCount === 0).length;

      return reply.send({
        success: true,
        data: {
          summary: { total: rows.length, allComplete, partial, notStarted },
          users: rows,
        },
      });
    }
  );
}
