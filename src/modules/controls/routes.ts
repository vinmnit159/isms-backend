import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { prisma } from '../../lib/prisma';
import { requirePermission } from '../../lib/rbac';
import { Permission, ControlStatus } from '../../lib/rbac';

const createControlSchema = z.object({
  isoReference: z.string().min(1),
  title: z.string().min(1),
  description: z.string(),
  status: z.nativeEnum(ControlStatus),
  justification: z.string().optional(),
});

const updateControlSchema = createControlSchema.partial();

export async function controlRoutes(app: FastifyInstance) {
  // Get all controls
  app.get('/', {
    onRequest: [requirePermission(Permission.READ_CONTROLS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const controls = await prisma.control.findMany({
        include: {
          evidence: true,
          riskMappings: {
            include: {
              risk: true,
            },
          },
          findings: true,
        },
        orderBy: {
          isoReference: 'asc',
        },
      });
      return reply.send({ success: true, data: controls });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to fetch controls',
        message: 'Could not retrieve controls from database',
      });
    }
  });

  // Get control by ID
  app.get('/:id', {
    onRequest: [requirePermission(Permission.READ_CONTROLS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      const control = await prisma.control.findUnique({
        where: { id },
        include: {
          evidence: true,
          riskMappings: {
            include: {
              risk: true,
            },
          },
          findings: true,
        },
      });

      if (!control) {
        return reply.status(404).send({
          success: false,
          error: 'Control not found',
          message: 'Control with the specified ID does not exist',
        });
      }

      return reply.send({ success: true, data: control });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to fetch control',
        message: 'Could not retrieve control from database',
      });
    }
  });

  // Create new control
  app.post('/', {
    onRequest: [requirePermission(Permission.WRITE_CONTROLS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const data = createControlSchema.parse(request.body);
      
      const control = await prisma.control.create({
        data: {
          ...data,
          organizationId: (request.user as any).organizationId,
        },
        include: {
          evidence: true,
          riskMappings: true,
          findings: true,
        },
      });

      return reply.status(201).send({
        success: true,
        data: control,
        message: 'Control created successfully',
      });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to create control',
        message: 'Could not create control in database',
      });
    }
  });

  // Update control
  app.put('/:id', {
    onRequest: [requirePermission(Permission.WRITE_CONTROLS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      const data = updateControlSchema.parse(request.body);

      const control = await prisma.control.update({
        where: { id },
        data,
        include: {
          evidence: true,
          riskMappings: {
            include: {
              risk: true,
            },
          },
          findings: true,
        },
      });

      return reply.send({
        success: true,
        data: control,
        message: 'Control updated successfully',
      });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to update control',
        message: 'Could not update control in database',
      });
    }
  });

  // Delete control
  app.delete('/:id', {
    onRequest: [requirePermission(Permission.DELETE_CONTROLS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      
      await prisma.control.delete({
        where: { id },
      });

      return reply.send({
        success: true,
        message: 'Control deleted successfully',
      });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to delete control',
        message: 'Could not delete control from database',
      });
    }
  });

  // Get control compliance status
  app.get('/compliance', {
    onRequest: [requirePermission(Permission.READ_CONTROLS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const compliance = await prisma.control.groupBy({
        by: ['status'],
        _count: {
          status: true,
        },
      });

      const total = compliance.reduce((sum, item) => sum + item._count.status, 0);
      
      const implemented = compliance.find(item => item.status === ControlStatus.IMPLEMENTED)?._count.status || 0;
      const partiallyImplemented = compliance.find(item => item.status === ControlStatus.PARTIALLY_IMPLEMENTED)?._count.status || 0;
      const notImplemented = compliance.find(item => item.status === ControlStatus.NOT_IMPLEMENTED)?._count.status || 0;
      const compliancePercentage = (implemented / total) * 100;

      const result = {
        total,
        implemented,
        partiallyImplemented,
        notImplemented,
        compliancePercentage: Math.round(compliancePercentage * 100) / 100,
      };

      return reply.send({ success: true, data: result });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to get compliance status',
        message: 'Could not calculate compliance metrics',
      });
    }
  });

  // Add evidence to control
  app.post('/:id/evidence', {
    onRequest: [requirePermission(Permission.WRITE_EVIDENCE)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      const { type, fileName, fileUrl, automated } = request.body as {
        type: string;
        fileName?: string;
        fileUrl?: string;
        automated?: boolean;
      };

      const evidence = await prisma.evidence.create({
        data: {
          type: type as any,
          fileName,
          fileUrl,
          hash: generateHash(),
          controlId: id,
          collectedBy: (request.user as any).id,
          automated: automated || false,
        },
      });

      return reply.status(201).send({
        success: true,
        data: evidence,
        message: 'Evidence added to control successfully',
      });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to add evidence',
        message: 'Could not add evidence to control',
      });
    }
  });
}

// Simple hash generation function (in production, use proper crypto)
function generateHash(): string {
  return `sha256:${Date.now()}:${Math.random().toString(36).substring(2)}`;
}