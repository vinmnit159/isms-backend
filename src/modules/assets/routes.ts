import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { prisma } from '../../lib/prisma';
import { requirePermission, Permission, AssetType, RiskLevel } from '../../lib/rbac';
import { logActivity } from '../../lib/activity-logger';

const createAssetSchema = z.object({
  name: z.string().min(1),
  type: z.nativeEnum(AssetType),
  ownerId: z.string().uuid(),
  criticality: z.nativeEnum(RiskLevel),
  description: z.string().optional(),
});

const updateAssetSchema = createAssetSchema.partial();

export async function assetRoutes(app: FastifyInstance) {
  // Get all assets
  app.get('/', {
    onRequest: [requirePermission(Permission.READ_ASSETS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const assets = await prisma.asset.findMany({
        include: {
          risks: true,
        },
        orderBy: {
          createdAt: 'desc',
        },
      });
      return reply.send({ success: true, data: assets });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to fetch assets',
        message: 'Could not retrieve assets from database',
      });
    }
  });

  // Get asset by ID
  app.get('/:id', {
    onRequest: [requirePermission(Permission.READ_ASSETS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      const asset = await prisma.asset.findUnique({
        where: { id },
        include: {
          risks: true,
        },
      });

      if (!asset) {
        return reply.status(404).send({
          success: false,
          error: 'Asset not found',
          message: 'Asset with the specified ID does not exist',
        });
      }

      return reply.send({ success: true, data: asset });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to fetch asset',
        message: 'Could not retrieve asset from database',
      });
    }
  });

  // Create new asset
  app.post('/', {
    onRequest: [requirePermission(Permission.WRITE_ASSETS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const data = createAssetSchema.parse(request.body);
      
      const asset = await prisma.asset.create({
        data: {
          name: data.name,
          type: data.type,
          ownerId: data.ownerId,
          criticality: data.criticality,
          description: data.description,
          organizationId: (request.user as any).organizationId,
        },
        include: {
          risks: true,
        },
      });

      logActivity((request.user as any).sub ?? (request.user as any).id, 'CREATED', 'ASSET', asset.id);
      return reply.status(201).send({
        success: true,
        data: asset,
        message: 'Asset created successfully',
      });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to create asset',
        message: 'Could not create asset in database',
      });
    }
  });

  // Update asset
  app.put('/:id', {
    onRequest: [requirePermission(Permission.WRITE_ASSETS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      const data = updateAssetSchema.parse(request.body);

      const asset = await prisma.asset.update({
        where: { id },
        data,
        include: {
          risks: true,
        },
      });

      logActivity((request.user as any).sub ?? (request.user as any).id, 'UPDATED', 'ASSET', asset.id);
      return reply.send({
        success: true,
        data: asset,
        message: 'Asset updated successfully',
      });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to update asset',
        message: 'Could not update asset in database',
      });
    }
  });

  // Delete asset
  app.delete('/:id', {
    onRequest: [requirePermission(Permission.DELETE_ASSETS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const { id } = request.params as { id: string };
      
      await prisma.asset.delete({ where: { id } });
      logActivity((request.user as any).sub ?? (request.user as any).id, 'DELETED', 'ASSET', id);
      return reply.send({
        success: true,
        message: 'Asset deleted successfully',
      });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to delete asset',
        message: 'Could not delete asset from database',
      });
    }
  });

  // Get critical assets
  app.get('/critical', {
    onRequest: [requirePermission(Permission.READ_ASSETS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const assets = await prisma.asset.findMany({
        where: {
          criticality: RiskLevel.CRITICAL,
        },
        include: {
          risks: true,
        },
        orderBy: {
          createdAt: 'desc',
        },
      });

      return reply.send({ success: true, data: assets });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to fetch critical assets',
        message: 'Could not retrieve critical assets',
      });
    }
  });

  // Get asset distribution by type
  app.get('/distribution', {
    onRequest: [requirePermission(Permission.READ_ASSETS)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const distribution = await prisma.asset.groupBy({
        by: ['type'],
        _count: {
          type: true,
        },
      });

      const total = distribution.reduce((sum, item) => sum + item._count.type, 0);
      
      const result = distribution.map(item => ({
        type: item.type,
        count: item._count.type,
        percentage: (item._count.type / total) * 100,
      }));

      return reply.send({ success: true, data: result });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        success: false,
        error: 'Failed to get asset distribution',
        message: 'Could not calculate asset distribution',
      });
    }
  });
}