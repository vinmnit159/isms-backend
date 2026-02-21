import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import axios from 'axios';
import { env } from '../../config/env';
import { encrypt, decrypt } from '../../lib/crypto';
import { prisma } from '../../lib/prisma';
import { authenticate } from '../../lib/auth-middleware';
import { fetchRepos, scanRepo } from './github-collector';
import { upsertAssetsAndRisks } from './github-asset-risk';
import { logActivity } from '../../lib/activity-logger';
import {
  getDriveAuthUrl,
  exchangeCodeForTokens,
  bootstrapFolderStructure,
} from './google-drive';
import { GitHubTestEvaluator, evalResultToTestStatus, EvaluatorContext } from './github-test-evaluator';

const ADMIN_ROLES = ['SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_OWNER'];

// The 13 predefined GitHub automated tests
const GITHUB_AUTOMATED_TESTS = [
  // Vulnerability
  'Medium vulnerabilities identified in packages are addressed (GitHub Repo)',
  'High vulnerabilities identified in packages are addressed (GitHub Repo)',
  'Critical vulnerabilities identified in packages are addressed (GitHub Repo)',
  'Low vulnerabilities identified in packages are addressed (GitHub Repo)',
  // Access & Identity
  'GitHub accounts associated with users',
  'All GitHub members must map to ISMS users',
  'GitHub accounts deprovisioned when personnel leave',
  'MFA on GitHub',
  // Code Review
  'GitHub code changes were approved or provided justification for exception',
  'Application changes reviewed',
  'Author is not the reviewer of pull requests',
  // Repository Governance
  'Company has a version control system',
  'GitHub repository visibility has been set to private',
] as const;

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

    // Seed automated tests idempotently on connect (fire-and-forget)
    seedAutomatedTests(orgId, fastify).catch((err) =>
      fastify.log.error(err, 'Automated test seeding on connect failed')
    );

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

  // ──────────────────────────────────────────────────────────────────────────
  // GET /integrations/google/connect — initiate Google Drive OAuth
  // Reads JWT from ?token= query param (browser redirect) or Authorization header
  // ──────────────────────────────────────────────────────────────────────────
  fastify.get('/google/connect', async (request: FastifyRequest, reply: FastifyReply) => {
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

    if (!env.GOOGLE_DRIVE_CLIENT_ID) {
      return reply.status(503).send({ error: 'Google Drive OAuth not configured on this server' });
    }

    const userId = user.sub ?? user.id;
    const url = getDriveAuthUrl(user.organizationId, userId);
    return reply.redirect(url);
  });

  // ──────────────────────────────────────────────────────────────────────────
  // GET /integrations/google/callback — exchange code for tokens, bootstrap folders
  // ──────────────────────────────────────────────────────────────────────────
  fastify.get('/google/callback', async (request: FastifyRequest, reply: FastifyReply) => {
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

    let tokens: Awaited<ReturnType<typeof exchangeCodeForTokens>>;
    try {
      tokens = await exchangeCodeForTokens(code);
    } catch (err: any) {
      fastify.log.error(err, 'Google Drive token exchange failed');
      return reply.redirect(`${frontendBase}/integrations?error=token_exchange_failed`);
    }

    // Persist encrypted tokens
    await prisma.integration.upsert({
      where: { organizationId_provider: { organizationId: orgId, provider: 'GOOGLE_DRIVE' } },
      update: {
        accessToken: encrypt(tokens.accessToken),
        refreshToken: encrypt(tokens.refreshToken),
        expiresAt: tokens.expiresAt,
        status: 'ACTIVE',
        connectedBy: userId,
      },
      create: {
        organizationId: orgId,
        provider: 'GOOGLE_DRIVE',
        accessToken: encrypt(tokens.accessToken),
        refreshToken: encrypt(tokens.refreshToken),
        expiresAt: tokens.expiresAt,
        status: 'ACTIVE',
        connectedBy: userId,
      },
    });

    logActivity(userId, 'CONNECTED', 'INTEGRATION', orgId);

    // Bootstrap folder structure — fire-and-forget, errors are non-fatal
    const org = await prisma.organization.findUnique({
      where: { id: orgId },
      select: { name: true },
    });
    bootstrapFolderStructure(orgId, org?.name ?? 'Org').catch((err) =>
      fastify.log.error(err, 'Google Drive folder bootstrap failed')
    );

    return reply.redirect(`${frontendBase}/integrations?connected=google_drive`);
  });

  // ──────────────────────────────────────────────────────────────────────────
  // DELETE /integrations/google — disconnect Google Drive
  // ──────────────────────────────────────────────────────────────────────────
  fastify.delete(
    '/google',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;
      const integration = await prisma.integration.findUnique({
        where: { organizationId_provider: { organizationId: user.organizationId, provider: 'GOOGLE_DRIVE' } },
      });
      if (!integration) return reply.status(404).send({ error: 'Google Drive not connected' });
      await prisma.integration.update({
        where: { id: integration.id },
        data: { status: 'DISCONNECTED' },
      });
      logActivity(user.sub ?? user.id, 'DISCONNECTED', 'INTEGRATION', user.organizationId);
      return reply.send({ success: true });
    }
  );

  // ──────────────────────────────────────────────────────────────────────────
  // POST /integrations/github/seed-tests
  // Idempotent — creates all 13 Engineering/Automated GitHub tests for the org.
  // Admin only.
  // ──────────────────────────────────────────────────────────────────────────
  fastify.post(
    '/github/seed-tests',
    { onRequest: [authenticate], schema: { body: { type: 'object' } } },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;
      if (!ADMIN_ROLES.includes(user?.role)) {
        return reply.status(403).send({ error: 'Forbidden' });
      }

      const integration = await prisma.integration.findUnique({
        where: { organizationId_provider: { organizationId: user.organizationId, provider: 'GITHUB' } },
      });
      if (!integration || integration.status !== 'ACTIVE') {
        return reply.status(400).send({ error: 'GitHub integration not connected or inactive' });
      }

      // Count existing before seed
      const before = await prisma.test.count({
        where: { organizationId: user.organizationId, integrationId: integration.id },
      });

      await seedAutomatedTests(user.organizationId, fastify);

      const after = await prisma.test.count({
        where: { organizationId: user.organizationId, integrationId: integration.id },
      });

      const created = after - before;
      const skipped = GITHUB_AUTOMATED_TESTS.length - created;

      logActivity(user.sub ?? user.id, 'CREATED', 'AUTOMATED_TESTS_SEED', user.organizationId);
      return reply.send({
        success: true,
        data: { created, skipped },
      });
    }
  );

  // ──────────────────────────────────────────────────────────────────────────
  // POST /integrations/github/run-tests
  // Runs all automated tests linked to this org's GitHub integration.
  // Stores results in Test.lastResult + IntegrationTestRun rows.
  // Admin only. Fire-and-forget model: returns immediately, runs in background.
  // ──────────────────────────────────────────────────────────────────────────
  fastify.post(
    '/github/run-tests',
    { onRequest: [authenticate], schema: { body: { type: 'object' } } },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;
      if (!ADMIN_ROLES.includes(user?.role)) {
        return reply.status(403).send({ error: 'Forbidden' });
      }

      const integration = await prisma.integration.findUnique({
        where: { organizationId_provider: { organizationId: user.organizationId, provider: 'GITHUB' } },
      });
      if (!integration || integration.status !== 'ACTIVE') {
        return reply.status(400).send({ error: 'GitHub integration not connected or inactive' });
      }

      const token = decrypt(integration.accessToken);
      logActivity(user.sub ?? user.id, 'SCANNED', 'INTEGRATION', user.organizationId);

      // Run in background — don't await
      runAutomatedTests(user.organizationId, integration.id, token, fastify).catch((err) =>
        fastify.log.error(err, 'Automated test run failed')
      );

      return reply.send({ success: true, message: 'Automated test run started in background' });
    }
  );

  // ──────────────────────────────────────────────────────────────────────────
  // GET /integrations/github/tests — list automated tests seeded for this org
  // ──────────────────────────────────────────────────────────────────────────
  fastify.get(
    '/github/tests',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;
      const integration = await prisma.integration.findUnique({
        where: { organizationId_provider: { organizationId: user.organizationId, provider: 'GITHUB' } },
      });
      if (!integration) return reply.send({ tests: [], seeded: false });

      const tests = await prisma.test.findMany({
        where: { organizationId: user.organizationId, integrationId: integration.id },
        orderBy: { name: 'asc' },
      });

      return reply.send({ success: true, data: tests, seeded: tests.length > 0 });
    }
  );
}

// ─── Automated test seeder ────────────────────────────────────────────────────
//
// Idempotently creates the 13 predefined Engineering/Automated tests linked to
// the org's GitHub integration. Safe to call multiple times (skips existing).
//

export async function seedAutomatedTests(
  organizationId: string,
  fastify: FastifyInstance
): Promise<void> {
  const integration = await prisma.integration.findUnique({
    where: { organizationId_provider: { organizationId, provider: 'GITHUB' } },
  });
  if (!integration || integration.status !== 'ACTIVE') return;

  const defaultOwner = await prisma.user.findFirst({
    where: { organizationId, role: { in: ['SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_OWNER'] as any } },
    select: { id: true },
  });
  const ownerId = defaultOwner?.id ?? integration.connectedBy;

  const dueDate = new Date();
  dueDate.setDate(dueDate.getDate() + 30);

  let created = 0;
  for (const name of GITHUB_AUTOMATED_TESTS) {
    const existing = await prisma.test.findFirst({
      where: { name, organizationId, integrationId: integration.id },
    });
    if (existing) continue;

    const t = await prisma.test.create({
      data: {
        name,
        category: 'Engineering' as any,
        type: 'Automated' as any,
        status: 'Due_soon' as any,
        lastResult: 'Not_Run' as any,
        ownerId,
        dueDate,
        organizationId,
        integrationId: integration.id,
        autoRemediationSupported: false,
      },
    });
    await prisma.testHistory.create({
      data: {
        testId: t.id,
        changedBy: 'system',
        changeType: 'CREATED',
        newValue: name,
      },
    });
    created++;
  }

  if (created > 0) {
    fastify.log.info(`Seeded ${created} automated tests for org ${organizationId}`);
  }
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

  // After repo sync, also run automated tests for this org
  await runAutomatedTests(organizationId, integration.id, token, fastify).catch((err: any) =>
    fastify.log.error(err, `Automated test run failed for org ${organizationId}`)
  );
}

// ─── Automated test runner ────────────────────────────────────────────────────
//
// Fetches all Engineering/Automated tests linked to integrationId, evaluates
// each via GitHubTestEvaluator (GitHub data is fetched once and cached), then
// writes results to Test.lastResult + IntegrationTestRun (append-only).
//

export async function runAutomatedTests(
  organizationId: string,
  integrationId: string,
  token: string,
  fastify: FastifyInstance
): Promise<void> {
  // Load linked automated tests
  const tests = await prisma.test.findMany({
    where: { organizationId, integrationId, type: 'Automated' },
  });

  if (tests.length === 0) {
    fastify.log.info(`No automated tests for org ${organizationId} / integration ${integrationId}`);
    return;
  }

  // Build evaluator context: collect linked GitHub usernames from UserGitAccount
  const gitAccounts = await prisma.userGitAccount.findMany({
    where: { organizationId },
    select: { githubUsername: true },
  });
  const context: EvaluatorContext = {
    linkedGitHubLogins: gitAccounts.map((a) => a.githubUsername.toLowerCase()),
  };

  const evaluator = new GitHubTestEvaluator(token);
  const now = new Date();

  for (const test of tests) {
    const start = Date.now();
    try {
      const evaluation = await evaluator.evaluateByName(test.name, context);
      const durationMs = Date.now() - start;
      const newStatus = evalResultToTestStatus(evaluation.status);

      // Update the test record
      await prisma.test.update({
        where: { id: test.id },
        data: {
          lastRunAt: now,
          lastResult: evaluation.status as any,
          lastResultDetails: evaluation.findings as any,
          status: newStatus as any,
          // Only mark completedAt if Pass and not already set
          completedAt: evaluation.status === 'Pass' && !test.completedAt ? now : test.completedAt,
        },
      });

      // Append-only run record
      await prisma.integrationTestRun.create({
        data: {
          integrationId,
          testId: test.id,
          status: evaluation.status as any,
          summary: evaluation.summary,
          rawPayload: { findings: evaluation.findings, rawData: evaluation.rawData } as any,
          executedAt: now,
          durationMs,
        },
      });

      // History entry
      await prisma.testHistory.create({
        data: {
          testId: test.id,
          changedBy: 'system',
          changeType: 'AUTO_RUN',
          oldValue: test.lastResult,
          newValue: evaluation.status,
        },
      });

      fastify.log.info(`Automated test "${test.name}" → ${evaluation.status}`);
    } catch (err: any) {
      fastify.log.error(err, `Failed to evaluate test "${test.name}"`);
      // Record a Fail run so we don't silently swallow errors
      await prisma.integrationTestRun.create({
        data: {
          integrationId,
          testId: test.id,
          status: 'Fail' as any,
          summary: `Evaluation error: ${err?.message ?? 'unknown'}`,
          executedAt: now,
          durationMs: Date.now() - start,
        },
      }).catch(() => {});
    }
  }

  // Auto-promote linked controls: if ALL tests for a control are OK → IMPLEMENTED
  for (const test of tests) {
    const controlMappings = await prisma.testControl.findMany({
      where: { testId: test.id },
      select: { controlId: true },
    });
    for (const { controlId } of controlMappings) {
      const allMappings = await prisma.testControl.findMany({
        where: { controlId },
        include: { test: { select: { status: true } } },
      });
      const allOK = allMappings.every((m: any) => m.test.status === 'OK');
      if (allOK) {
        await prisma.control.update({
          where: { id: controlId },
          data: { status: 'IMPLEMENTED' as any },
        });
      }
    }
  }

  fastify.log.info(`Automated tests complete for org ${organizationId}: ${tests.length} tests run`);
}
