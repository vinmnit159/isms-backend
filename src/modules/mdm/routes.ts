/**
 * MDM Admin Routes — /api/mdm
 * Manages enrollment tokens and provides device/compliance views for admins.
 */
import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import crypto from 'crypto';
import { prisma } from '../../lib/prisma';
import { authenticate } from '../../lib/auth-middleware';
import { logActivity } from '../../lib/activity-logger';

const ADMIN_ROLES = ['SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_OWNER'];
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

function requireAdmin(request: FastifyRequest, reply: FastifyReply, done: () => void) {
  const role = (request as any).user?.role;
  if (!ADMIN_ROLES.includes(role)) {
    reply.status(403).send({ error: 'Forbidden', message: 'Admin role required' });
    return;
  }
  done();
}

export async function mdmRoutes(fastify: FastifyInstance) {

  // ── POST /api/mdm/tokens — create an enrollment token ──────────────────────
  fastify.post(
    '/tokens',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;
      if (!ADMIN_ROLES.includes(user.role)) {
        return reply.status(403).send({ error: 'Forbidden', message: 'Admin role required' });
      }

      const { label } = (request.body as any) ?? {};
      const token = crypto.randomBytes(20).toString('hex'); // 40-char hex
      const expiresAt = new Date(Date.now() + TOKEN_TTL_MS);

      const record = await prisma.enrollmentToken.create({
        data: {
          token,
          organizationId: user.organizationId,
          createdBy: user.sub ?? user.id,
          label: label ?? null,
          expiresAt,
        },
      });

      logActivity(user.sub ?? user.id, 'CREATED', 'ENROLLMENT_TOKEN', record.id);

      return reply.status(201).send({
        id: record.id,
        token,
        label: record.label,
        expiresAt: record.expiresAt,
        createdAt: record.createdAt,
        // Convenience install command
        installCommand: `sudo bash <(curl -fsSL https://raw.githubusercontent.com/vinmnit159/manzen-mdm-agent/main/scripts/install.sh) --token ${token}`,
      });
    }
  );

  // ── GET /api/mdm/tokens — list tokens ──────────────────────────────────────
  fastify.get(
    '/tokens',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;
      if (!ADMIN_ROLES.includes(user.role)) {
        return reply.status(403).send({ error: 'Forbidden', message: 'Admin role required' });
      }

      const tokens = await prisma.enrollmentToken.findMany({
        where: { organizationId: user.organizationId },
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          label: true,
          usedAt: true,
          expiresAt: true,
          createdAt: true,
          createdBy: true,
        },
      });

      return reply.send({ tokens });
    }
  );

  // ── DELETE /api/mdm/tokens/:id — revoke a token ────────────────────────────
  fastify.delete(
    '/tokens/:id',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;
      if (!ADMIN_ROLES.includes(user.role)) {
        return reply.status(403).send({ error: 'Forbidden', message: 'Admin role required' });
      }

      const { id } = request.params as any;
      await prisma.enrollmentToken.deleteMany({
        where: { id, organizationId: user.organizationId },
      });

      return reply.send({ success: true });
    }
  );

  // ── GET /api/mdm/devices — list all managed devices ────────────────────────
  fastify.get(
    '/devices',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;

      const assets = await prisma.asset.findMany({
        where: {
          organizationId: user.organizationId,
          type: 'ENDPOINT',
          enrollment: { isNot: null },
        },
        include: {
          compliance: true,
          enrollment: {
            select: {
              id: true,
              enrolledAt: true,
              lastSeenAt: true,
              revoked: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
      });

      return reply.send({ devices: assets });
    }
  );

  // ── GET /api/mdm/devices/:id/checkins — checkin history ────────────────────
  fastify.get(
    '/devices/:id/checkins',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id } = request.params as any;
      const user = (request as any).user;
      const { limit = '20' } = request.query as any;

      // Verify device belongs to org
      const asset = await prisma.asset.findFirst({
        where: { id, organizationId: user.organizationId },
      });
      if (!asset) return reply.status(404).send({ error: 'Not found' });

      const checkins = await prisma.deviceCheckin.findMany({
        where: { assetId: id },
        orderBy: { receivedAt: 'desc' },
        take: Math.min(Number(limit), 100),
      });

      return reply.send({ checkins });
    }
  );

  // ── DELETE /api/mdm/devices/:id — revoke a device ──────────────────────────
  fastify.delete(
    '/devices/:id',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;
      if (!ADMIN_ROLES.includes(user.role)) {
        return reply.status(403).send({ error: 'Forbidden', message: 'Admin role required' });
      }

      const { id } = request.params as any;
      const asset = await prisma.asset.findFirst({
        where: { id, organizationId: user.organizationId },
      });
      if (!asset) return reply.status(404).send({ error: 'Not found' });

      await prisma.deviceEnrollment.updateMany({
        where: { assetId: id },
        data: { revoked: true },
      });

      logActivity(user.sub ?? user.id, 'UPDATED', 'DEVICE_ENROLLMENT', id);
      return reply.send({ success: true });
    }
  );

  // ── PATCH /api/mdm/devices/:id/owner — reassign device owner ──────────────
  fastify.patch(
    '/devices/:id/owner',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;
      if (!ADMIN_ROLES.includes(user.role)) {
        return reply.status(403).send({ error: 'Forbidden', message: 'Admin role required' });
      }

      const { id } = request.params as any;
      const { ownerId } = (request.body as any) ?? {};

      if (!ownerId || typeof ownerId !== 'string') {
        return reply.status(400).send({ error: 'ownerId is required' });
      }

      // Verify the asset belongs to this org and is an enrolled endpoint
      const asset = await prisma.asset.findFirst({
        where: { id, organizationId: user.organizationId, type: 'ENDPOINT' },
      });
      if (!asset) return reply.status(404).send({ error: 'Device not found' });

      // Verify the new owner belongs to the same org
      const newOwner = await prisma.user.findFirst({
        where: { id: ownerId, organizationId: user.organizationId },
        select: { id: true, name: true, email: true },
      });
      if (!newOwner) return reply.status(404).send({ error: 'User not found in organisation' });

      const updated = await prisma.asset.update({
        where: { id },
        data: { ownerId },
        include: {
          compliance: true,
          enrollment: {
            select: { id: true, enrolledAt: true, lastSeenAt: true, revoked: true },
          },
        },
      });

      logActivity(user.sub ?? user.id, 'UPDATED', 'ASSET', id);
      return reply.send({ device: updated, newOwner });
    }
  );

  // ── GET /api/mdm/overview — dashboard stats ────────────────────────────────
  fastify.get(
    '/overview',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;

      const [total, compliant, nonCompliant] = await Promise.all([
        prisma.asset.count({
          where: {
            organizationId: user.organizationId,
            type: 'ENDPOINT',
            enrollment: { isNot: null },
          },
        }),
        prisma.deviceCompliance.count({
          where: {
            complianceStatus: 'COMPLIANT',
            asset: { organizationId: user.organizationId },
          },
        }),
        prisma.deviceCompliance.count({
          where: {
            complianceStatus: 'NON_COMPLIANT',
            asset: { organizationId: user.organizationId },
          },
        }),
      ]);

      return reply.send({
        total,
        compliant,
        nonCompliant,
        unknown: total - compliant - nonCompliant,
      });
    }
  );
}
