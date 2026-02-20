/**
 * Agent Routes — /api/agent  (unauthenticated or device-key authenticated)
 * Handles device enrollment and periodic check-ins from the Go MDM agent.
 */
import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { prisma } from '../../lib/prisma';
import { logActivity } from '../../lib/activity-logger';

// ── ISO control → compliance check mapping ────────────────────────────────────
// Used by the auto-risk engine to create/close risks based on device posture.
const COMPLIANCE_RULES = [
  {
    field: 'diskEncryptionEnabled',
    isoRef: 'A.8.24',
    riskTitle: 'Endpoint without disk encryption',
    description: 'A managed device does not have full-disk encryption enabled (FileVault). This exposes data to physical theft.',
    impact: 'HIGH' as const,
    likelihood: 'MEDIUM' as const,
    score: 12,
  },
  {
    field: 'screenLockEnabled',
    isoRef: 'A.5.15',
    riskTitle: 'Device without automatic screen lock',
    description: 'A managed device does not require a password after screensaver activation, violating access control policy.',
    impact: 'MEDIUM' as const,
    likelihood: 'MEDIUM' as const,
    score: 9,
  },
  {
    field: 'firewallEnabled',
    isoRef: 'A.8.20',
    riskTitle: 'Endpoint firewall disabled',
    description: 'A managed device is running without an active host-based firewall, increasing network attack surface.',
    impact: 'MEDIUM' as const,
    likelihood: 'LOW' as const,
    score: 6,
  },
  {
    field: 'systemIntegrityEnabled',
    isoRef: 'A.8.7',
    riskTitle: 'System Integrity Protection disabled on endpoint',
    description: 'SIP has been disabled on a managed device, reducing protection against rootkits and malware.',
    impact: 'HIGH' as const,
    likelihood: 'LOW' as const,
    score: 8,
  },
  {
    field: 'autoUpdateEnabled',
    isoRef: 'A.8.8',
    riskTitle: 'Automatic OS updates disabled on endpoint',
    description: 'A managed device has automatic software updates turned off, leaving it potentially unpatched.',
    impact: 'MEDIUM' as const,
    likelihood: 'HIGH' as const,
    score: 12,
  },
];

// ── Helper: find control by ISO reference ─────────────────────────────────────
async function findControl(organizationId: string, isoRef: string) {
  return prisma.control.findFirst({
    where: { organizationId, isoReference: { contains: isoRef } },
    select: { id: true },
  });
}

// ── Auto-risk engine ──────────────────────────────────────────────────────────
async function runRiskEngine(
  asset: { id: string; organizationId: string; name: string },
  posture: Record<string, boolean>
) {
  for (const rule of COMPLIANCE_RULES) {
    const passing = !!posture[rule.field];
    const control = await findControl(asset.organizationId, rule.isoRef);

    if (!passing) {
      // Ensure an OPEN risk exists for this device + rule
      const existing = await prisma.risk.findFirst({
        where: {
          assetId: asset.id,
          title: rule.riskTitle,
          status: 'OPEN',
        },
      });
      if (!existing) {
        const risk = await prisma.risk.create({
          data: {
            title: rule.riskTitle,
            description: `${rule.description}\n\nDevice: ${asset.name}`,
            impact: rule.impact,
            likelihood: rule.likelihood,
            riskScore: rule.score,
            status: 'OPEN',
            assetId: asset.id,
          },
        });
        // Auto-create evidence link to control
        if (control) {
          const hash = crypto.createHash('sha256')
            .update(`${asset.id}:${rule.isoRef}:noncompliant`)
            .digest('hex');
          const evidenceExists = await prisma.evidence.findFirst({ where: { hash } });
          if (!evidenceExists) {
            await prisma.evidence.create({
              data: {
                type: 'AUTOMATED',
                hash,
                controlId: control.id,
                collectedBy: 'mdm-agent',
                automated: true,
                fileName: `mdm-${asset.name.replace(/\s/g, '-')}-${rule.isoRef}.json`,
              },
            });
          }
          // Link risk to control via treatment
          await prisma.riskTreatment.create({
            data: { riskId: risk.id, controlId: control.id },
          }).catch(() => {/* already linked */});
        }
      }
    } else {
      // Device is now compliant — auto-mitigate open risks for this rule
      await prisma.risk.updateMany({
        where: {
          assetId: asset.id,
          title: rule.riskTitle,
          status: 'OPEN',
        },
        data: { status: 'MITIGATED' },
      });
    }
  }
}

// ── Determine overall compliance status ───────────────────────────────────────
function calcComplianceStatus(posture: Record<string, boolean>): 'COMPLIANT' | 'NON_COMPLIANT' {
  const criticalChecks = COMPLIANCE_RULES.map((r) => r.field);
  const failing = criticalChecks.filter((f) => !posture[f]);
  return failing.length === 0 ? 'COMPLIANT' : 'NON_COMPLIANT';
}

// ── Route handler ─────────────────────────────────────────────────────────────
export async function agentRoutes(fastify: FastifyInstance) {

  // ── POST /api/agent/enroll ────────────────────────────────────────────────
  fastify.post('/enroll', async (request: FastifyRequest, reply: FastifyReply) => {
    const {
      enrollmentToken,
      hostname,
      osType,
      osVersion,
      serialNumber,
    } = request.body as any;

    if (!enrollmentToken || !hostname) {
      return reply.status(400).send({ error: 'enrollmentToken and hostname are required' });
    }

    // Validate token
    const tokenRecord = await prisma.enrollmentToken.findUnique({
      where: { token: enrollmentToken },
    });

    if (!tokenRecord) {
      return reply.status(401).send({ error: 'Invalid enrollment token' });
    }
    if (tokenRecord.usedAt) {
      return reply.status(409).send({ error: 'Enrollment token already used' });
    }
    if (new Date() > tokenRecord.expiresAt) {
      return reply.status(410).send({ error: 'Enrollment token expired' });
    }

    const { organizationId, createdBy } = tokenRecord;

    // Find the org's admin user to use as ownerId
    const orgAdmin = await prisma.user.findFirst({
      where: { organizationId, role: { in: ['ORG_ADMIN', 'SUPER_ADMIN', 'SECURITY_OWNER'] } },
      select: { id: true },
    });
    const ownerId = orgAdmin?.id ?? createdBy;

    // Upsert asset (ENDPOINT type) — match on serial number or hostname
    let asset = await prisma.asset.findFirst({
      where: {
        organizationId,
        OR: [
          serialNumber ? { serialNumber } : {},
          { hostname, type: 'ENDPOINT' },
        ],
      },
    });

    if (!asset) {
      asset = await prisma.asset.create({
        data: {
          name: hostname,
          type: 'ENDPOINT',
          ownerId,
          criticality: 'HIGH',
          organizationId,
          hostname,
          osType,
          osVersion,
          serialNumber: serialNumber ?? null,
          status: 'ACTIVE',
          description: `Managed Mac endpoint — enrolled via MDM agent`,
        },
      });
    } else {
      asset = await prisma.asset.update({
        where: { id: asset.id },
        data: { hostname, osType, osVersion, serialNumber: serialNumber ?? undefined, status: 'ACTIVE' },
      });
    }

    // Issue API key
    const rawApiKey = crypto.randomBytes(32).toString('hex');
    const apiKeyHash = await bcrypt.hash(rawApiKey, 10);

    await prisma.deviceEnrollment.upsert({
      where: { assetId: asset.id },
      update: { apiKeyHash, enrolledAt: new Date(), lastSeenAt: new Date(), revoked: false },
      create: {
        assetId: asset.id,
        apiKeyHash,
        organizationId,
        enrolledAt: new Date(),
        lastSeenAt: new Date(),
      },
    });

    // Mark token as used
    await prisma.enrollmentToken.update({
      where: { id: tokenRecord.id },
      data: { usedAt: new Date() },
    });

    logActivity(createdBy, 'CREATED', 'DEVICE_ENROLLMENT', asset.id);

    return reply.status(201).send({
      deviceId: asset.id,
      apiKey: rawApiKey, // sent once — never stored in plaintext
    });
  });

  // ── POST /api/agent/checkin ───────────────────────────────────────────────
  fastify.post('/checkin', async (request: FastifyRequest, reply: FastifyReply) => {
    const authHeader = request.headers.authorization;
    const deviceId = (request.headers['x-device-id'] as string) ?? (request.body as any)?.deviceId;

    if (!authHeader || !deviceId) {
      return reply.status(401).send({ error: 'Missing Authorization or X-Device-ID header' });
    }

    const rawKey = authHeader.replace('Bearer ', '');

    // Load enrollment — verify API key
    const enrollment = await prisma.deviceEnrollment.findFirst({
      where: { assetId: deviceId, revoked: false },
    });

    if (!enrollment) {
      return reply.status(401).send({ error: 'Device not enrolled or revoked' });
    }

    const valid = await bcrypt.compare(rawKey, enrollment.apiKeyHash);
    if (!valid) {
      return reply.status(401).send({ error: 'Invalid API key' });
    }

    // Load asset
    const asset = await prisma.asset.findUnique({ where: { id: deviceId } });
    if (!asset) return reply.status(404).send({ error: 'Device asset not found' });

    const { posture } = request.body as any;
    if (!posture) {
      return reply.status(400).send({ error: 'posture is required' });
    }

    // Store raw check-in for audit trail
    await prisma.deviceCheckin.create({
      data: {
        assetId: deviceId,
        payloadJson: posture,
      },
    });

    // Update asset OS info
    await prisma.asset.update({
      where: { id: deviceId },
      data: {
        osVersion: posture.osVersion ?? undefined,
        hostname: posture.hostname ?? undefined,
      },
    });

    // Upsert compliance snapshot
    const complianceStatus = calcComplianceStatus(posture);
    await prisma.deviceCompliance.upsert({
      where: { assetId: deviceId },
      update: {
        diskEncryptionEnabled: !!posture.diskEncryptionEnabled,
        screenLockEnabled: !!posture.screenLockEnabled,
        firewallEnabled: !!posture.firewallEnabled,
        antivirusEnabled: !!posture.antivirusEnabled,
        systemIntegrityEnabled: !!posture.systemIntegrityProtectionEnabled,
        autoUpdateEnabled: !!posture.autoUpdateEnabled,
        gatekeeperEnabled: !!posture.gatekeeperEnabled,
        complianceStatus,
        lastCheckedAt: new Date(),
      },
      create: {
        assetId: deviceId,
        diskEncryptionEnabled: !!posture.diskEncryptionEnabled,
        screenLockEnabled: !!posture.screenLockEnabled,
        firewallEnabled: !!posture.firewallEnabled,
        antivirusEnabled: !!posture.antivirusEnabled,
        systemIntegrityEnabled: !!posture.systemIntegrityProtectionEnabled,
        autoUpdateEnabled: !!posture.autoUpdateEnabled,
        gatekeeperEnabled: !!posture.gatekeeperEnabled,
        complianceStatus,
      },
    });

    // Update last-seen
    await prisma.deviceEnrollment.update({
      where: { id: enrollment.id },
      data: { lastSeenAt: new Date() },
    });

    // Run auto-risk engine (fire-and-forget)
    runRiskEngine(asset, posture).catch((e) => fastify.log.error(e, 'Risk engine error'));

    return reply.send({ ok: true, complianceStatus });
  });
}
