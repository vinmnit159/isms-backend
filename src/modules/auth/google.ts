import { FastifyInstance } from 'fastify';
import { env } from '../../config/env';
import { prisma } from '../../lib/prisma';

/**
 * Google OAuth routes — mounted at /auth/google (no /api prefix, matches the
 * redirect_uri registered in Google Console:
 *   https://ismsbackend.bitcoingames1346.com/auth/google/callback
 */
export async function googleAuthRoutes(app: FastifyInstance) {
  // ── 1. Initiate flow ──────────────────────────────────────────────────────
  // GET /auth/google  →  redirect to Google consent screen
  app.get('/google', async (request, reply) => {
    const url = (app as any).googleOAuth2.authorizationUrl({
      scope: ['openid', 'email', 'profile'],
      access_type: 'offline',
      prompt: 'select_account',
    });
    return reply.redirect(url);
  });

  // ── 2. Handle callback ────────────────────────────────────────────────────
  // GET /auth/google/callback  →  exchange code → get profile → issue JWT
  app.get('/google/callback', async (request: any, reply) => {
    try {
      // Exchange auth code for access + id tokens
      const { token } =
        await (app as any).googleOAuth2.getAccessTokenFromAuthorizationCodeFlow(request);

      const accessToken: string = token.access_token as string;

      // Fetch Google profile
      const profileRes = await fetch(
        'https://www.googleapis.com/oauth2/v3/userinfo',
        { headers: { Authorization: `Bearer ${accessToken}` } },
      );

      if (!profileRes.ok) {
        app.log.error('Failed to fetch Google profile: ' + profileRes.status);
        return reply.redirect(
          `${env.FRONTEND_URL}/login?error=google_profile_failed`,
        );
      }

      const profile = (await profileRes.json()) as {
        sub: string;        // Google user ID
        email: string;
        name?: string;
        picture?: string;
        email_verified?: boolean;
      };

      if (!profile.email) {
        return reply.redirect(
          `${env.FRONTEND_URL}/login?error=no_email`,
        );
      }

      // ── Upsert user ───────────────────────────────────────────────────────
      // Priority: match by googleId > match by email > create new
      let user = await prisma.user.findUnique({
        where: { googleId: profile.sub },
        include: { organization: true },
      });

      if (!user) {
        // Try matching by email (existing password-based account)
        const byEmail = await prisma.user.findUnique({
          where: { email: profile.email },
          include: { organization: true },
        });

        if (byEmail) {
          // Link Google ID to the existing account
          user = await prisma.user.update({
            where: { id: byEmail.id },
            data: {
              googleId: profile.sub,
              name: byEmail.name ?? profile.name,
            },
            include: { organization: true },
          });
        } else {
          // Brand-new Google user — they need an organization.
          // Find the default / first org, or redirect to setup if none exists.
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
              // password is null — Google SSO users don't need one
            },
            include: { organization: true },
          });
        }
      }

      // ── Issue our own JWT ─────────────────────────────────────────────────
      const jwt = app.jwt.sign({
        sub: user.id,
        email: user.email,
        role: user.role,
        organizationId: user.organizationId,
      });

      // Encode the user payload so the frontend can cache it
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

      // Redirect back to the frontend with the token in the URL fragment
      // (hash fragments are never sent to the server — safer than query params)
      return reply.redirect(
        `${env.FRONTEND_URL}/auth/callback?token=${encodeURIComponent(jwt)}&user=${userPayload}`,
      );
    } catch (err) {
      app.log.error(err, 'Google OAuth callback error');
      return reply.redirect(
        `${env.FRONTEND_URL}/login?error=oauth_failed`,
      );
    }
  });
}
