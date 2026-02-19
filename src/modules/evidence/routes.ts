import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import fs from 'fs';
import path from 'path';
import { prisma } from '../../lib/prisma';
import { requirePermission, Permission } from '../../lib/rbac';
import { saveUploadedFile, deleteStoredFile, UPLOAD_DIR } from '../../lib/file-storage';

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
      const evidence = await prisma.evidence.findUnique({ where: { id } });
      if (evidence?.fileUrl?.startsWith('/files/')) {
        deleteStoredFile(evidence.fileUrl.replace('/files/', ''));
      }
      await prisma.evidence.delete({ where: { id } });
      return reply.send({ success: true, message: 'Evidence deleted' });
    }
  );

  // POST /api/evidence/upload — upload a file as evidence for a control
  app.post(
    '/upload',
    { onRequest: [requirePermission(Permission.WRITE_CONTROLS)] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const user = request.user as any;

        const fileField = await request.file();
        if (!fileField) {
          return reply.status(400).send({ success: false, error: 'No file provided' });
        }

        // controlId is passed as a form field in the multipart body
        const controlId = (fileField.fields as any)?.controlId?.value as string | undefined;
        if (!controlId) {
          return reply.status(400).send({ success: false, error: 'controlId is required' });
        }

        // Verify the control belongs to the user's org
        const control = await prisma.control.findFirst({
          where: { id: controlId, organizationId: user.organizationId },
        });
        if (!control) {
          return reply.status(404).send({ success: false, error: 'Control not found' });
        }

        const stored = await saveUploadedFile(fileField, 'evidence');

        const evidence = await prisma.evidence.create({
          data: {
            type: 'FILE',
            fileName: stored.originalName,
            fileUrl: stored.fileUrl,
            hash: `manual-${Date.now()}-${Math.random().toString(36).slice(2)}`,
            controlId,
            collectedBy: user.email ?? user.id,
            automated: false,
          },
          include: {
            control: { select: { id: true, isoReference: true, title: true, status: true } },
          },
        });

        return reply.status(201).send({
          success: true,
          data: evidence,
          message: 'Evidence file uploaded successfully',
        });
      } catch (error) {
        app.log.error(error);
        return reply.status(500).send({ success: false, error: 'Failed to upload evidence file' });
      }
    }
  );

  // GET /api/evidence/:id/download — download evidence file (authenticated)
  app.get(
    '/:id/download',
    { onRequest: [requirePermission(Permission.READ_CONTROLS)] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const { id } = request.params as any;

        const evidence = await prisma.evidence.findUnique({
          where: { id },
          include: { control: { select: { organizationId: true } } },
        });

        if (!evidence) {
          return reply.status(404).send({ success: false, error: 'Evidence not found' });
        }

        if (!evidence.fileUrl) {
          return reply.status(404).send({ success: false, error: 'No file attached to this evidence' });
        }

        // If it's a local file, stream it
        if (evidence.fileUrl.startsWith('/files/')) {
          const relPath = evidence.fileUrl.replace('/files/', '');
          const absPath = path.join(UPLOAD_DIR, relPath);

          if (!fs.existsSync(absPath)) {
            return reply.status(404).send({ success: false, error: 'File not found on server' });
          }

          const fileName = evidence.fileName ?? path.basename(absPath);
          reply.header('Content-Disposition', `attachment; filename="${fileName}"`);
          return reply.sendFile(relPath);
        }

        // External URL — redirect
        return reply.redirect(evidence.fileUrl);
      } catch (error) {
        app.log.error(error);
        return reply.status(500).send({ success: false, error: 'Failed to download evidence file' });
      }
    }
  );
}
