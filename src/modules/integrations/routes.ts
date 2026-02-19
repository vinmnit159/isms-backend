import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import axios from 'axios';
import { env } from '../../config/env';
import { encrypt, decrypt } from '../../lib/crypto';
import { prisma } from '../../lib/prisma';
import { authenticate } from '../../lib/auth-middleware';
import { fetchRepos, scanRepo } from './github-collector';
import { upsertAssetsAndRisks } from './github-asset-risk';
import { logActivity } from '../../lib/activity-logger';

// ISO control reference → DB lookup
async function findControlId(organizationId: string, isoReference: string): Promise<string | null> {
  const ctrl = await prisma.control.findFirst({
    where: { organizationId, isoReference: { contains: isoReference } },
    select: { id: true },
  });
  return ctrl?.id ?? null;
}

async function upsertEvidenceForScan(organizationId: string, scanData: Record<string, any>) {
  const checks = [
    scanData.branchProtection,
    scanData.commitSigning,
    scanData.cicd,
    scanData.accessControl,
    scanData.repoMeta,
  ].filter(Boolean);

  for (const check of checks) {
    const controlId = await findControlId(organizationId, check.result.controlRef);
    if (!controlId) continue;
    const existing = await prisma.evidence.findFirst({
      where: { controlId, hash: check.hash },
    });
    if (!existing) {
      await prisma.evidence.create({
        data: {
          type: 'AUTOMATED',
          hash: check.hash,
          controlId,
          collectedBy: 'system',
          automated: true,
          fileName: `github-${check.result.repo?.replace('/', '-') ?? 'scan'}-${check.result.controlRef}.json`,
          fileUrl: null,
        },
      });
    }
  }
}

export async function integrationRoutes(fastify: FastifyInstance) {

  // ──────────────────────────────────────────────────────────────────────────
  // GET /integrations/status
  // ──────────────────────────────────────────────────────────────────────────
  fastify.get(
    '/status',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;
      const integrations = await prisma.integration.findMany({
        where: { organizationId: user.organizationId },
        select: {
          id: true,
          provider: true,
          status: true,
          createdAt: true,
          updatedAt: true,
          repos: {
            select: {
              id: true,
              name: true,
              fullName: true,
              private: true,
              defaultBranch: true,
              visibility: true,
              lastScannedAt: true,
              rawData: true,
            },
          },
        },
      });
      return reply.send({ integrations });
    }
  );

  // ──────────────────────────────────────────────────────────────────────────
  // GET /integrations/github/connect — initiate GitHub OAuth
  // Reads JWT from ?token= query param (browser redirect) or Authorization header
  // ──────────────────────────────────────────────────────────────────────────
  fastify.get('/github/connect', async (request: FastifyRequest, reply: FastifyReply) => {
    const query = request.query as any;
    let user: any;
    try {
      if (query.token) {
        user = fastify.jwt.verify(query.token);
      } else {
        await (request as any).jwtVerify();
        user = (request as any).user;
      }
    } catch {
      return reply.status(401).send({ error: 'Unauthorized' });
    }

    if (!env.GITHUB_CLIENT_ID) {
      return reply.status(503).send({ error: 'GitHub OAuth not configured on this server' });
    }

    // JWT uses `sub` for user id (see auth/routes.ts sign call)
    const userId = user.sub ?? user.id;
    const state = Buffer.from(
      JSON.stringify({ orgId: user.organizationId, userId })
    ).toString('base64url');

    const params = new URLSearchParams({
      client_id: env.GITHUB_CLIENT_ID,
      redirect_uri: env.GITHUB_CALLBACK_URL,
      scope: 'repo read:org read:user admin:repo_hook',
      state,
    });

    return reply.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
  });

  // ──────────────────────────────────────────────────────────────────────────
  // GET /integrations/github/callback — exchange code for token
  // ──────────────────────────────────────────────────────────────────────────
  fastify.get('/github/callback', async (request: FastifyRequest, reply: FastifyReply) => {
    const { code, state, error } = request.query as any;
    const frontendBase = env.FRONTEND_URL;

    if (error) {
      return reply.redirect(`${frontendBase}/integrations?error=${encodeURIComponent(error)}`);
    }
    if (!code || !state) {
      return reply.redirect(`${frontendBase}/integrations?error=missing_params`);
    }

    let orgId: string;
    let userId: string;
    try {
      const decoded = JSON.parse(Buffer.from(state, 'base64url').toString('utf8'));
      orgId = decoded.orgId;
      userId = decoded.userId ?? decoded.sub ?? 'system';
    } catch {
      return reply.redirect(`${frontendBase}/integrations?error=invalid_state`);
    }

    if (!orgId || !userId) {
      return reply.redirect(`${frontendBase}/integrations?error=invalid_state`);
    }

    let accessToken: string;
    try {
      const { data } = await axios.post(
        'https://github.com/login/oauth/access_token',
        {
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: env.GITHUB_CALLBACK_URL,
        },
        { headers: { Accept: 'application/json' } }
      );
      if (data.error) {
        return reply.redirect(
          `${frontendBase}/integrations?error=${encodeURIComponent(data.error_description ?? data.error)}`
        );
      }
      accessToken = data.access_token;
    } catch (err: any) {
      fastify.log.error(err, 'GitHub token exchange failed');
      return reply.redirect(`${frontendBase}/integrations?error=token_exchange_failed`);
    }

    const encryptedToken = encrypt(accessToken);
    await prisma.integration.upsert({
      where: { organizationId_provider: { organizationId: orgId, provider: 'GITHUB' } },
      update: { accessToken: encryptedToken, status: 'ACTIVE', connectedBy: userId },
      create: {
        organizationId: orgId,
        provider: 'GITHUB',
        accessToken: encryptedToken,
        status: 'ACTIVE',
        connectedBy: userId,
      },
    });

    // Log the connection event
    logActivity(userId, 'CONNECTED', 'INTEGRATION', orgId);

    // Fire-and-forget initial sync
    syncRepos(orgId, accessToken, fastify).catch((err) =>
      fastify.log.error(err, 'Initial GitHub repo sync failed')
    );

    return reply.redirect(`${frontendBase}/integrations?connected=github`);
  });

  // ──────────────────────────────────────────────────────────────────────────
  // DELETE /integrations/github — disconnect
  // ──────────────────────────────────────────────────────────────────────────
  fastify.delete(
    '/github',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;
      const integration = await prisma.integration.findUnique({
        where: { organizationId_provider: { organizationId: user.organizationId, provider: 'GITHUB' } },
      });
      if (!integration) return reply.status(404).send({ error: 'GitHub not connected' });
      await prisma.integration.update({
        where: { id: integration.id },
        data: { status: 'DISCONNECTED' },
      });
      return reply.send({ success: true });
    }
  );

  // ──────────────────────────────────────────────────────────────────────────
  // POST /integrations/github/scan — manual scan trigger
  // ──────────────────────────────────────────────────────────────────────────
  fastify.post(
    '/github/scan',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;
      const integration = await prisma.integration.findUnique({
        where: { organizationId_provider: { organizationId: user.organizationId, provider: 'GITHUB' } },
      });
      if (!integration || integration.status !== 'ACTIVE') {
        return reply.status(400).send({ error: 'GitHub not connected or inactive' });
      }
      const token = decrypt(integration.accessToken);
      logActivity(user.sub ?? user.id, 'SCANNED', 'INTEGRATION', user.organizationId);
      syncRepos(user.organizationId, token, fastify).catch((err) =>
        fastify.log.error(err, 'Manual GitHub scan failed')
      );
      return reply.send({ success: true, message: 'GitHub scan started in background' });
    }
  );

  // ──────────────────────────────────────────────────────────────────────────
  // GET /integrations/github/repos — list repos
  // ──────────────────────────────────────────────────────────────────────────
  fastify.get(
    '/github/repos',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;
      const integration = await prisma.integration.findUnique({
        where: { organizationId_provider: { organizationId: user.organizationId, provider: 'GITHUB' } },
        include: { repos: { orderBy: { createdAt: 'desc' } } },
      });
      if (!integration || integration.status !== 'ACTIVE') {
        return reply.status(400).send({ error: 'GitHub not connected' });
      }
      return reply.send({ repos: integration.repos });
    }
  );

  // ──────────────────────────────────────────────────────────────────────────
  // GET /integrations/github/repos/:repoId/scan — scan data for one repo
  // ──────────────────────────────────────────────────────────────────────────
  fastify.get(
    '/github/repos/:repoId/scan',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { repoId } = request.params as any;
      const user = (request as any).user;
      const repo = await prisma.gitHubRepo.findFirst({
        where: { id: repoId, integration: { organizationId: user.organizationId } },
      });
      if (!repo) return reply.status(404).send({ error: 'Repo not found' });
      return reply.send({ repo });
    }
  );
}

// ─── Shared sync helper ───────────────────────────────────────────────────────

export async function syncRepos(
  organizationId: string,
  token: string,
  fastify: FastifyInstance
) {
  const repos = await fetchRepos(token);

  const integration = await prisma.integration.findUnique({
    where: { organizationId_provider: { organizationId, provider: 'GITHUB' } },
  });
  if (!integration) return;

  // Resolve the org admin user id to use as asset ownerId
  const orgAdmin = await prisma.user.findFirst({
    where: { organizationId, role: { in: ['ORG_ADMIN', 'SUPER_ADMIN', 'SECURITY_OWNER'] } },
    select: { id: true },
  });
  const ownerId = orgAdmin?.id ?? integration.connectedBy;

  const scanResults = new Map<number, any>();

  for (const repo of repos) {
    const scanResult = await scanRepo(token, repo);
    scanResults.set(repo.id, scanResult);

    await prisma.gitHubRepo.upsert({
      where: { integrationId_githubId: { integrationId: integration.id, githubId: repo.id } },
      update: {
        name: repo.name,
        fullName: repo.full_name,
        private: repo.private,
        defaultBranch: repo.default_branch,
        visibility: repo.visibility ?? (repo.private ? 'private' : 'public'),
        lastScannedAt: new Date(),
        rawData: scanResult as any,
      },
      create: {
        integrationId: integration.id,
        githubId: repo.id,
        name: repo.name,
        fullName: repo.full_name,
        private: repo.private,
        defaultBranch: repo.default_branch,
        visibility: repo.visibility ?? (repo.private ? 'private' : 'public'),
        lastScannedAt: new Date(),
        rawData: scanResult as any,
      },
    });

    await upsertEvidenceForScan(organizationId, scanResult).catch((err) =>
      fastify.log.error(err, `Evidence upsert failed for ${repo.full_name}`)
    );
  }

  // Create/update Assets and Risks from scan results
  await upsertAssetsAndRisks(organizationId, ownerId, repos, scanResults).catch((err) =>
    fastify.log.error(err, 'Asset/Risk upsert from GitHub scan failed')
  );

  fastify.log.info(`GitHub sync complete for org ${organizationId}: ${repos.length} repos`);
}
