import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { prisma } from '../../lib/prisma';
import { requirePermission } from '../../lib/rbac';
import { Permission, RiskLevel, RiskStatus } from '../../lib/rbac';

const createRiskSchema = z.object({
  title: z.string().min(1),
  description: z.string(),
  impact: z.nativeEnum(RiskLevel),
  likelihood: z.nativeEnum(RiskLevel),
  assetId: z.string().uuid(),
});

const updateRiskSchema = createRiskSchema.partial();

export async function riskRoutes(app: FastifyInstance) {
  // Get all risks
  app.get('/', {
    onRequest: [requirePermission(Permission.READ_RISKS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const risks = await prisma.risk.findMany({
        include: {
          asset: true,
          treatments: {
            include: {
              control: true,
            },
          },
        },
        orderBy: {
          createdAt: 'desc',
        },
      });
      return reply.send({ success: true, data: risks });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to fetch risks',
        message: 'Could not retrieve risks from database',
      });
    }
  });

  // Get risk by ID
  app.get('/:id', {
    onRequest: [requirePermission(Permission.READ_RISKS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      const risk = await prisma.risk.findUnique({
        where: { id },
        include: {
          asset: true,
          treatments: {
            include: {
              control: true,
            },
          },
        },
      });

      if (!risk) {
        return reply.status(404).send({
          success: false,
          error: 'Risk not found',
          message: 'Risk with the specified ID does not exist',
        });
      }

      return reply.send({ success: true, data: risk });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to fetch risk',
        message: 'Could not retrieve risk from database',
      });
    }
  });

  // Create new risk
  app.post('/', {
    onRequest: [requirePermission(Permission.WRITE_RISKS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const data = createRiskSchema.parse(request.body);
      
      // Calculate risk score based on impact and likelihood
      const impactValue = getRiskValue(data.impact);
      const likelihoodValue = getRiskValue(data.likelihood);
      const riskScore = impactValue * likelihoodValue;
      
      const risk = await prisma.risk.create({
        data: {
          ...data,
          riskScore,
          organizationId: request.user.organizationId,
        },
        include: {
          asset: true,
          treatments: {
            include: {
              control: true,
            },
          },
        },
      });

      return reply.status(201).send({
        success: true,
        data: risk,
        message: 'Risk created successfully',
      });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to create risk',
        message: 'Could not create risk in database',
      });
    }
  });

  // Update risk
  app.put('/:id', {
    onRequest: [requirePermission(Permission.WRITE_RISKS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      const data = updateRiskSchema.parse(request.body);

      // Calculate risk score if impact or likelihood provided
      let updateData: any = { ...data };
      if (data.impact || data.likelihood) {
        const existingRisk = await prisma.risk.findUnique({ where: { id } });
        if (existingRisk) {
          const impactValue = getRiskValue(data.impact || existingRisk.impact);
          const likelihoodValue = getRiskValue(data.likelihood || existingRisk.likelihood);
          updateData.riskScore = impactValue * likelihoodValue;
        }
      }

      const risk = await prisma.risk.update({
        where: { id },
        data: updateData,
        include: {
          asset: true,
          treatments: {
            include: {
              control: true,
            },
          },
        },
      });

      return reply.send({
        success: true,
        data: risk,
        message: 'Risk updated successfully',
      });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to update risk',
        message: 'Could not update risk in database',
      });
    }
  });

  // Delete risk
  app.delete('/:id', {
    onRequest: [requirePermission(Permission.DELETE_RISKS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      
      await prisma.risk.delete({
        where: { id },
      });

      return reply.send({
        success: true,
        message: 'Risk deleted successfully',
      });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to delete risk',
        message: 'Could not delete risk from database',
      });
    }
  });

  // Get risk distribution
  app.get('/distribution', {
    onRequest: [requirePermission(Permission.READ_RISKS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const distribution = await prisma.risk.groupBy({
        by: ['impact'],
        _count: {
          impact: true,
        },
      });

      const total = distribution.reduce((sum, item) => sum + item._count.impact, 0);
      
      const result = distribution.map(item => ({
        level: item.impact,
        count: item._count.impact,
        percentage: (item._count.impact / total) * 100,
      }));

      return reply.send({ success: true, data: result });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to get risk distribution',
        message: 'Could not calculate risk distribution',
      });
    }
  });

  // Add risk treatment
  app.post('/treatment', {
    onRequest: [requirePermission(Permission.WRITE_RISKS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { riskId, controlId, notes } = request.body as {
        riskId: string;
        controlId: string;
        notes?: string;
      };

      const treatment = await prisma.riskTreatment.create({
        data: {
          riskId,
          controlId,
          notes,
        },
        include: {
          risk: true,
          control: true,
        },
      });

      return reply.status(201).send({
        success: true,
        data: treatment,
        message: 'Risk treatment added successfully',
      });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to add risk treatment',
        message: 'Could not create risk treatment',
      });
    }
  });
}

// Helper function to convert risk levels to numeric values
function getRiskValue(level: RiskLevel): number {
  switch (level) {
    case RiskLevel.LOW:
      return 1;
    case RiskLevel.MEDIUM:
      return 2;
    case RiskLevel.HIGH:
      return 3;
    case RiskLevel.CRITICAL:
      return 4;
    default:
      return 1;
  }
}