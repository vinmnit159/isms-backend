import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { prisma } from '../../lib/prisma';
import { requirePermission } from '../../lib/rbac';
import { Permission } from '../../lib/rbac';

const createPolicySchema = z.object({
  name: z.string().min(1, 'Policy name is required'),
  version: z.string().min(1, 'Version is required'),
  status: z.string().min(1, 'Status is required'),
  documentUrl: z.string().default(''),
  approvedBy: z.string().optional(),
  approvedAt: z.string().datetime().optional(),
});

const updatePolicySchema = createPolicySchema.partial();

export async function policyRoutes(app: FastifyInstance) {
  // GET /api/policies — list all policies for the user's organization
  app.get('/', {
    onRequest: [requirePermission(Permission.READ_CONTROLS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const user = request.user as any;
      const { search, status } = request.query as { search?: string; status?: string };

      const policies = await prisma.policy.findMany({
        where: {
          organizationId: user.organizationId,
          ...(status ? { status } : {}),
          ...(search
            ? {
                name: {
                  contains: search,
                  mode: 'insensitive' as const,
                },
              }
            : {}),
        },
        orderBy: { createdAt: 'desc' },
      });

      return reply.send({ success: true, data: policies });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to fetch policies',
        message: 'Could not retrieve policies from database',
      });
    }
  });

  // GET /api/policies/:id — get single policy
  app.get('/:id', {
    onRequest: [requirePermission(Permission.READ_CONTROLS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      const user = request.user as any;

      const policy = await prisma.policy.findFirst({
        where: { id, organizationId: user.organizationId },
      });

      if (!policy) {
        return reply.status(404).send({
          success: false,
          error: 'Policy not found',
          message: 'Policy with the specified ID does not exist',
        });
      }

      return reply.send({ success: true, data: policy });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to fetch policy',
        message: 'Could not retrieve policy from database',
      });
    }
  });

  // POST /api/policies — create policy
  app.post('/', {
    onRequest: [requirePermission(Permission.WRITE_CONTROLS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const user = request.user as any;
      const data = createPolicySchema.parse(request.body);

      const policy = await prisma.policy.create({
        data: {
          ...data,
          approvedAt: data.approvedAt ? new Date(data.approvedAt) : undefined,
          organizationId: user.organizationId,
        },
      });

      return reply.status(201).send({
        success: true,
        data: policy,
        message: 'Policy created successfully',
      });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to create policy',
        message: 'Could not create policy in database',
      });
    }
  });

  // PUT /api/policies/:id — update policy
  app.put('/:id', {
    onRequest: [requirePermission(Permission.WRITE_CONTROLS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      const user = request.user as any;
      const data = updatePolicySchema.parse(request.body);

      // Ensure policy belongs to the user's org
      const existing = await prisma.policy.findFirst({
        where: { id, organizationId: user.organizationId },
      });

      if (!existing) {
        return reply.status(404).send({
          success: false,
          error: 'Policy not found',
          message: 'Policy with the specified ID does not exist',
        });
      }

      const policy = await prisma.policy.update({
        where: { id },
        data: {
          ...data,
          approvedAt: data.approvedAt ? new Date(data.approvedAt) : undefined,
        },
      });

      return reply.send({
        success: true,
        data: policy,
        message: 'Policy updated successfully',
      });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to update policy',
        message: 'Could not update policy in database',
      });
    }
  });

  // DELETE /api/policies/:id — delete policy
  app.delete('/:id', {
    onRequest: [requirePermission(Permission.DELETE_CONTROLS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      const user = request.user as any;

      const existing = await prisma.policy.findFirst({
        where: { id, organizationId: user.organizationId },
      });

      if (!existing) {
        return reply.status(404).send({
          success: false,
          error: 'Policy not found',
          message: 'Policy with the specified ID does not exist',
        });
      }

      await prisma.policy.delete({ where: { id } });

      return reply.send({
        success: true,
        message: 'Policy deleted successfully',
      });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to delete policy',
        message: 'Could not delete policy from database',
      });
    }
  });
}
