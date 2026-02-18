import { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { AuthorizationCode } from 'simple-oauth2';
import { randomBytes } from 'crypto';
import { env } from '../../config/env';
import { prisma } from '../../lib/prisma';

// In-memory state store (maps state → expiry). Fine for a single-instance
// server. For multi-instance deployments, swap for Redis/DB.
const pendingStates = new Map<string, number>();

function createOAuthClient() {
  return new AuthorizationCode({
    client: {
      id: env.GOOGLE_CLIENT_ID,
      secret: env.GOOGLE_CLIENT_SECRET,
    },
    auth: {
      tokenHost: 'https://oauth2.googleapis.com',
      tokenPath: '/token',
      authorizeHost: 'https://accounts.google.com',
      authorizePath: '/o/oauth2/v2/auth',
    },
  });
}

/**
 * Register Google OAuth routes as a fastify-plugin (skips encapsulation so
 * app.jwt is visible, and participates correctly in Fastify 4 lifecycle).
 *
 * GET /auth/google          → redirect to Google consent screen
 * GET /auth/google/callback → exchange code, upsert user, issue JWT
 */
async function googlePlugin(app: FastifyInstance) {
  // ── Initiate ───────────────────────────────────────────────────────────────
  app.get('/auth/google', async (_request, reply) => {
    const client = createOAuthClient();
    const state = randomBytes(16).toString('hex');

    // Store state with a 10-minute expiry
    pendingStates.set(state, Date.now() + 10 * 60 * 1000);

    // Cleanup expired states
    for (const [s, exp] of pendingStates) {
      if (Date.now() > exp) pendingStates.delete(s);
    }

    const authorizationUri = client.authorizeURL({
      redirect_uri: env.GOOGLE_CALLBACK_URL,
      scope: 'openid email profile',
      state,
      access_type: 'offline',
      prompt: 'select_account',
    } as any);

    return reply.redirect(authorizationUri);
  });

  // ── Callback ───────────────────────────────────────────────────────────────
  app.get('/auth/google/callback', async (request: any, reply) => {
    try {
      const { code, state, error } = request.query as {
        code?: string;
        state?: string;
        error?: string;
      };

      // Google returned an error (e.g. user denied consent)
      if (error) {
        app.log.warn('Google OAuth error: ' + error);
        return reply.redirect(`${env.FRONTEND_URL}/login?error=oauth_denied`);
      }

      // Validate state to prevent CSRF
      if (!state || !pendingStates.has(state)) {
        app.log.warn('Invalid OAuth state: ' + state);
        return reply.redirect(`${env.FRONTEND_URL}/login?error=invalid_state`);
      }
      if (Date.now() > pendingStates.get(state)!) {
        pendingStates.delete(state);
        return reply.redirect(`${env.FRONTEND_URL}/login?error=state_expired`);
      }
      pendingStates.delete(state);

      if (!code) {
        return reply.redirect(`${env.FRONTEND_URL}/login?error=no_code`);
      }

      // Exchange code for tokens
      const client = createOAuthClient();
      const tokenResult = await client.getToken({
        code,
        redirect_uri: env.GOOGLE_CALLBACK_URL,
      });

      const accessToken = (tokenResult.token as any).access_token as string;

      if (!accessToken) {
        app.log.error('No access_token in Google token response');
        return reply.redirect(`${env.FRONTEND_URL}/login?error=oauth_failed`);
      }

      // Fetch Google user profile
      const profileRes = await fetch(
        'https://www.googleapis.com/oauth2/v3/userinfo',
        { headers: { Authorization: `Bearer ${accessToken}` } },
      );

      if (!profileRes.ok) {
        app.log.error('Google userinfo failed: ' + profileRes.status);
        return reply.redirect(`${env.FRONTEND_URL}/login?error=google_profile_failed`);
      }

      const profile = (await profileRes.json()) as {
        sub: string;
        email: string;
        name?: string;
        picture?: string;
        email_verified?: boolean;
      };

      if (!profile.email) {
        return reply.redirect(`${env.FRONTEND_URL}/login?error=no_email`);
      }

      // ── Upsert user ─────────────────────────────────────────────────────────
      // 1. Match by googleId  2. Match by email (link existing account)  3. Create
      let user = await prisma.user.findUnique({
        where: { googleId: profile.sub },
        include: { organization: true },
      });

      if (!user) {
        const byEmail = await prisma.user.findUnique({
          where: { email: profile.email },
          include: { organization: true },
        });

        if (byEmail) {
          user = await prisma.user.update({
            where: { id: byEmail.id },
            data: {
              googleId: profile.sub,
              name: byEmail.name ?? profile.name,
            },
            include: { organization: true },
          });
        } else {
          const defaultOrg = await prisma.organization.findFirst();
          if (!defaultOrg) {
            return reply.redirect(
              `${env.FRONTEND_URL}/register?error=no_org&email=${encodeURIComponent(profile.email)}`,
            );
          }
          user = await prisma.user.create({
            data: {
              email: profile.email,
              name: profile.name ?? profile.email,
              googleId: profile.sub,
              role: 'VIEWER',
              organizationId: defaultOrg.id,
            },
            include: { organization: true },
          });
        }
      }

      // ── Issue our JWT ────────────────────────────────────────────────────────
      const jwt = app.jwt.sign({
        sub: user.id,
        email: user.email,
        role: user.role,
        organizationId: user.organizationId,
      });

      const userPayload = encodeURIComponent(
        JSON.stringify({
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          organizationId: user.organizationId,
          organization: user.organization,
          createdAt: user.createdAt,
        }),
      );

      return reply.redirect(
        `${env.FRONTEND_URL}/auth/callback?token=${encodeURIComponent(jwt)}&user=${userPayload}`,
      );
    } catch (err) {
      app.log.error(err, 'Google OAuth callback error');
      return reply.redirect(`${env.FRONTEND_URL}/login?error=oauth_failed`);
    }
  });
}

export const registerGoogleCallback = fp(googlePlugin, {
  name: 'google-oauth',
  fastify: '4.x',
});
