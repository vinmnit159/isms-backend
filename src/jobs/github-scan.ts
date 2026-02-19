import cron from 'node-cron';
import { PrismaClient } from '@prisma/client';
import { FastifyInstance } from 'fastify';
import { decrypt } from '../lib/crypto';
import { syncRepos } from '../modules/integrations/routes';

const prisma = new PrismaClient();

export function startGitHubScanJob(fastify: FastifyInstance) {
  // Run every 24 hours at 02:00 UTC
  cron.schedule('0 2 * * *', async () => {
    fastify.log.info('GitHub scan cron: starting scheduled scan for all active integrations');

    const integrations = await prisma.integration.findMany({
      where: { provider: 'GITHUB', status: 'ACTIVE' },
      select: { organizationId: true, accessToken: true },
    });

    fastify.log.info(`GitHub scan cron: found ${integrations.length} active integrations`);

    for (const integration of integrations) {
      try {
        const token = decrypt(integration.accessToken);
        await syncRepos(integration.organizationId, token, fastify);
      } catch (err) {
        fastify.log.error(err, `GitHub cron scan failed for org ${integration.organizationId}`);
      }
    }

    fastify.log.info('GitHub scan cron: completed');
  });

  fastify.log.info('GitHub scan cron job registered (runs daily at 02:00 UTC)');
}
