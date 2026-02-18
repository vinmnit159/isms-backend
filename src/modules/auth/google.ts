import { FastifyInstance } from 'fastify';
import { env } from '../../config/env';
import { prisma } from '../../lib/prisma';

/**
 * Register the Google OAuth callback route directly on the root Fastify
 * instance so the `googleOAuth2` decorator (added by @fastify/oauth2) is
 * available.
 *
 * NOTE: @fastify/oauth2 automatically registers GET /auth/google (the
 * startRedirectPath) — we must NOT re-register that path ourselves.
 * We only need to handle the callback.
 *
 * Registered route:
 *   GET /auth/google/callback
 *   → must exactly match the redirect_uri in Google Cloud Console
 */
export function registerGoogleCallback(app: FastifyInstance) {
  app.get('/auth/google/callback', async (request: any, reply: any) => {
    try {
      // Exchange the auth code for tokens
      const { token } =
        await (app as any).googleOAuth2.getAccessTokenFromAuthorizationCodeFlow(request);

      const accessToken: string = token.access_token as string;

      // Fetch the user's Google profile
      const profileRes = await fetch(
        'https://www.googleapis.com/oauth2/v3/userinfo',
        { headers: { Authorization: `Bearer ${accessToken}` } },
      );

      if (!profileRes.ok) {
        app.log.error('Failed to fetch Google profile, status: ' + profileRes.status);
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

      // ── Upsert user ────────────────────────────────────────────────────────
      // 1. Match by googleId  2. Match by email (link account)  3. Create new
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
          // Link Google ID to the existing password-based account
          user = await prisma.user.update({
            where: { id: byEmail.id },
            data: {
              googleId: profile.sub,
              name: byEmail.name ?? profile.name,
            },
            include: { organization: true },
          });
        } else {
          // Brand-new Google user — assign to the first org in the DB
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
              // password intentionally null — Google SSO users don't need one
            },
            include: { organization: true },
          });
        }
      }

      // ── Issue our own JWT ──────────────────────────────────────────────────
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

      // Redirect to the frontend callback page with the JWT
      return reply.redirect(
        `${env.FRONTEND_URL}/auth/callback?token=${encodeURIComponent(jwt)}&user=${userPayload}`,
      );
    } catch (err) {
      app.log.error(err, 'Google OAuth callback error');
      return reply.redirect(`${env.FRONTEND_URL}/login?error=oauth_failed`);
    }
  });
}
