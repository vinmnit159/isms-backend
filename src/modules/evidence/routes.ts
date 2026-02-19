import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { prisma } from '../../lib/prisma';
import { requirePermission, Permission } from '../../lib/rbac';

export async function evidenceRoutes(app: FastifyInstance) {
  // GET /api/evidence — list all evidence with control info
  app.get(
    '/',
    { onRequest: [requirePermission(Permission.READ_CONTROLS)] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const { controlId, automated, search } = request.query as any;
        const where: any = {};
        if (controlId) where.controlId = controlId;
        if (automated !== undefined) where.automated = automated === 'true';
        if (search) {
          where.OR = [
            { fileName: { contains: search, mode: 'insensitive' } },
            { collectedBy: { contains: search, mode: 'insensitive' } },
          ];
        }
        const evidence = await prisma.evidence.findMany({
          where,
          include: {
            control: {
              select: { id: true, isoReference: true, title: true, status: true },
            },
          },
          orderBy: { createdAt: 'desc' },
        });
        return reply.send({ success: true, data: evidence });
      } catch (err) {
        app.log.error(err);
        return reply.status(500).send({ success: false, error: 'Failed to fetch evidence' });
      }
    }
  );

  // GET /api/evidence/stats — summary counts
  app.get(
    '/stats',
    { onRequest: [requirePermission(Permission.READ_CONTROLS)] },
    async (_request: FastifyRequest, reply: FastifyReply) => {
      try {
        const [total, automated, byType] = await Promise.all([
          prisma.evidence.count(),
          prisma.evidence.count({ where: { automated: true } }),
          prisma.evidence.groupBy({ by: ['type'], _count: { type: true } }),
        ]);
        return reply.send({
          success: true,
          data: {
            total,
            automated,
            manual: total - automated,
            byType: byType.map((b) => ({ type: b.type, count: b._count.type })),
          },
        });
      } catch (err) {
        app.log.error(err);
        return reply.status(500).send({ success: false, error: 'Failed to fetch evidence stats' });
      }
    }
  );

  // GET /api/evidence/:id
  app.get(
    '/:id',
    { onRequest: [requirePermission(Permission.READ_CONTROLS)] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id } = request.params as any;
      const evidence = await prisma.evidence.findUnique({
        where: { id },
        include: { control: true },
      });
      if (!evidence) return reply.status(404).send({ success: false, error: 'Evidence not found' });
      return reply.send({ success: true, data: evidence });
    }
  );

  // DELETE /api/evidence/:id
  app.delete(
    '/:id',
    { onRequest: [requirePermission(Permission.WRITE_CONTROLS)] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id } = request.params as any;
      await prisma.evidence.delete({ where: { id } });
      return reply.send({ success: true, message: 'Evidence deleted' });
    }
  );
}
