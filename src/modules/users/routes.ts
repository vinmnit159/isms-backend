import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { prisma } from '../../lib/prisma';
import { authenticate } from '../../lib/auth-middleware';
import { logActivity } from '../../lib/activity-logger';
import { decrypt } from '../../lib/crypto';
import axios from 'axios';

const USER_SELECT = {
  id: true,
  email: true,
  name: true,
  role: true,
  organizationId: true,
  createdAt: true,
  gitAccounts: {
    select: {
      id: true,
      githubUsername: true,
      githubId: true,
      avatarUrl: true,
      profileUrl: true,
    },
  },
};

export async function userRoutes(app: FastifyInstance) {

  // ──────────────────────────────────────────────────────────────────────────
  // GET /api/users — list all users in the organisation
  // ──────────────────────────────────────────────────────────────────────────
  app.get(
    '/',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;
      const users = await prisma.user.findMany({
        where: { organizationId: user.organizationId },
        select: USER_SELECT,
        orderBy: { createdAt: 'asc' },
      });
      return reply.send({ users });
    }
  );

  // ──────────────────────────────────────────────────────────────────────────
  // GET /api/users/:id — get single user
  // ──────────────────────────────────────────────────────────────────────────
  app.get(
    '/:id',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id } = request.params as any;
      const requester = (request as any).user;

      const user = await prisma.user.findFirst({
        where: { id, organizationId: requester.organizationId },
        select: USER_SELECT,
      });

      if (!user) {
        return reply.status(404).send({ error: 'Not found', message: 'User not found' });
      }

      return reply.send({ user });
    }
  );

  // ──────────────────────────────────────────────────────────────────────────
  // PUT /api/users/:id — update user role (admin only)
  // ──────────────────────────────────────────────────────────────────────────
  app.put(
    '/:id',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id } = request.params as any;
      const requester = (request as any).user;

      // Only admins can change roles
      const adminRoles = ['SUPER_ADMIN', 'ORG_ADMIN'];
      if (!adminRoles.includes(requester.role)) {
        return reply.status(403).send({ error: 'Forbidden', message: 'Only admins can update user roles' });
      }

      const { role, name } = request.body as { role?: string; name?: string };

      const validRoles = ['SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_OWNER', 'AUDITOR', 'CONTRIBUTOR', 'VIEWER'];
      if (role && !validRoles.includes(role)) {
        return reply.status(400).send({ error: 'Validation error', message: `Invalid role: ${role}` });
      }

      // Ensure user belongs to same org
      const existing = await prisma.user.findFirst({
        where: { id, organizationId: requester.organizationId },
      });
      if (!existing) {
        return reply.status(404).send({ error: 'Not found', message: 'User not found' });
      }

      const updated = await prisma.user.update({
        where: { id },
        data: {
          ...(role ? { role: role as any } : {}),
          ...(name ? { name: name.trim() } : {}),
        },
        select: USER_SELECT,
      });

      logActivity(requester.sub ?? requester.id, 'UPDATED', 'USER', id);

      return reply.send({ user: updated });
    }
  );

  // ──────────────────────────────────────────────────────────────────────────
  // DELETE /api/users/:id — remove a user (admin only, cannot self-delete)
  // ──────────────────────────────────────────────────────────────────────────
  app.delete(
    '/:id',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id } = request.params as any;
      const requester = (request as any).user;

      const adminRoles = ['SUPER_ADMIN', 'ORG_ADMIN'];
      if (!adminRoles.includes(requester.role)) {
        return reply.status(403).send({ error: 'Forbidden', message: 'Only admins can remove users' });
      }

      const requesterId = requester.sub ?? requester.id;
      if (id === requesterId) {
        return reply.status(400).send({ error: 'Bad request', message: 'You cannot remove your own account' });
      }

      const existing = await prisma.user.findFirst({
        where: { id, organizationId: requester.organizationId },
      });
      if (!existing) {
        return reply.status(404).send({ error: 'Not found', message: 'User not found' });
      }

      await prisma.user.delete({ where: { id } });
      logActivity(requesterId, 'DELETED', 'USER', id);

      return reply.send({ success: true });
    }
  );

  // ──────────────────────────────────────────────────────────────────────────
  // GET /api/users/git-accounts — list all linked GitHub accounts for the org
  // ──────────────────────────────────────────────────────────────────────────
  app.get(
    '/git-accounts/list',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;
      const accounts = await prisma.userGitAccount.findMany({
        where: { organizationId: user.organizationId },
        include: {
          user: {
            select: { id: true, name: true, email: true, role: true },
          },
        },
        orderBy: { createdAt: 'asc' },
      });
      return reply.send({ accounts });
    }
  );

  // ──────────────────────────────────────────────────────────────────────────
  // GET /api/users/git-accounts/github-members — fetch org members from GitHub API
  // Requires an active GitHub integration for the org
  // ──────────────────────────────────────────────────────────────────────────
  app.get(
    '/git-accounts/github-members',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = (request as any).user;

      const integration = await prisma.integration.findUnique({
        where: {
          organizationId_provider: {
            organizationId: user.organizationId,
            provider: 'GITHUB',
          },
        },
      });

      if (!integration || integration.status !== 'ACTIVE') {
        // No integration — return empty list, not an error
        return reply.send({ members: [], connected: false });
      }

      try {
        const token = decrypt(integration.accessToken);

        // Fetch the authenticated user's orgs to find the relevant GitHub org
        const { data: ghUser } = await axios.get('https://api.github.com/user', {
          headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' },
        });

        // Fetch repos to derive the org name (use login from authenticated user / org collaborators)
        // Try fetching members of all orgs the token belongs to
        const { data: orgs } = await axios.get('https://api.github.com/user/orgs', {
          headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' },
        });

        let members: any[] = [];

        if (orgs && orgs.length > 0) {
          // Fetch members for the first org
          const orgLogin = orgs[0].login;
          const { data: orgMembers } = await axios.get(
            `https://api.github.com/orgs/${orgLogin}/members`,
            {
              headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' },
              params: { per_page: 100 },
            }
          );
          members = orgMembers.map((m: any) => ({
            githubId: m.id,
            githubUsername: m.login,
            avatarUrl: m.avatar_url,
            profileUrl: m.html_url,
          }));
        } else {
          // Personal account — just return the authenticated user
          members = [
            {
              githubId: ghUser.id,
              githubUsername: ghUser.login,
              avatarUrl: ghUser.avatar_url,
              profileUrl: ghUser.html_url,
            },
          ];
        }

        // Enrich with mapping info — which ISMS user each GitHub account is linked to
        const linked = await prisma.userGitAccount.findMany({
          where: { organizationId: user.organizationId },
          select: { githubUsername: true, userId: true },
        });
        const linkedMap = new Map(linked.map((l) => [l.githubUsername, l.userId]));

        const enriched = members.map((m: any) => ({
          ...m,
          mappedUserId: linkedMap.get(m.githubUsername) ?? null,
        }));

        return reply.send({ members: enriched, connected: true });
      } catch (err: any) {
        app.log.error(err, 'Failed to fetch GitHub members');
        return reply.status(502).send({
          error: 'GitHub API error',
          message: 'Failed to fetch GitHub members',
        });
      }
    }
  );

  // ──────────────────────────────────────────────────────────────────────────
  // POST /api/users/git-accounts/map — link a GitHub account to an ISMS user
  // Body: { userId, githubUsername, githubId?, avatarUrl?, profileUrl? }
  // ──────────────────────────────────────────────────────────────────────────
  app.post(
    '/git-accounts/map',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const requester = (request as any).user;
      const { userId, githubUsername, githubId, avatarUrl, profileUrl } = request.body as any;

      if (!userId || !githubUsername) {
        return reply.status(400).send({
          error: 'Validation error',
          message: 'userId and githubUsername are required',
        });
      }

      // Verify target user belongs to same org
      const targetUser = await prisma.user.findFirst({
        where: { id: userId, organizationId: requester.organizationId },
      });
      if (!targetUser) {
        return reply.status(404).send({ error: 'Not found', message: 'User not found' });
      }

      const account = await prisma.userGitAccount.upsert({
        where: {
          organizationId_githubUsername: {
            organizationId: requester.organizationId,
            githubUsername,
          },
        },
        update: { userId, githubId, avatarUrl, profileUrl },
        create: {
          userId,
          githubUsername,
          githubId,
          avatarUrl,
          profileUrl,
          organizationId: requester.organizationId,
        },
        include: {
          user: { select: { id: true, name: true, email: true, role: true } },
        },
      });

      logActivity(requester.sub ?? requester.id, 'UPDATED', 'USER_GIT_ACCOUNT', account.id);

      return reply.send({ account });
    }
  );

  // ──────────────────────────────────────────────────────────────────────────
  // DELETE /api/users/git-accounts/:id — unlink a GitHub account
  // ──────────────────────────────────────────────────────────────────────────
  app.delete(
    '/git-accounts/:id',
    { onRequest: [authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const { id } = request.params as any;
      const requester = (request as any).user;

      const account = await prisma.userGitAccount.findFirst({
        where: { id, organizationId: requester.organizationId },
      });
      if (!account) {
        return reply.status(404).send({ error: 'Not found', message: 'Git account mapping not found' });
      }

      await prisma.userGitAccount.delete({ where: { id } });
      logActivity(requester.sub ?? requester.id, 'DELETED', 'USER_GIT_ACCOUNT', id);

      return reply.send({ success: true });
    }
  );
}
