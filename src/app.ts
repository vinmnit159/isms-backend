import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import fastifyJwt from '@fastify/jwt';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';

import { env } from './config/env';
import { swaggerPlugin } from './plugins/swagger';
import { authenticate } from './lib/auth-middleware';
import { authRoutes } from './modules/auth/routes';
import { registerGoogleCallback } from './modules/auth/google';
import { assetRoutes } from './modules/assets/routes';
import { riskRoutes } from './modules/risks/routes';
import { controlRoutes } from './modules/controls/routes';
import { evidenceRoutes } from './modules/evidence/routes';
import { auditRoutes } from './modules/audits/routes';
import { userRoutes } from './modules/users/routes';
import { setupRoutes } from './modules/setup/routes';
import { policyRoutes } from './modules/policies/routes';

export const app: FastifyInstance = Fastify({
  logger: {
    level: env.LOG_LEVEL,
  },
});

// Register plugins
app.register(helmet);
app.register(cors, {
  origin: [
    env.CORS_ORIGIN,
    'https://isms.bitcoingames1346.com'
  ],
  credentials: true,
});

// Register JWT directly on the root app instance (no encapsulation wrapper)
// so app.jwt.sign() is available in all route handlers
app.register(fastifyJwt, {
  secret: env.JWT_SECRET,
  sign: {
    expiresIn: env.JWT_EXPIRES_IN,
  },
});

app.register(swaggerPlugin);

// Add authentication decorator
app.decorate('authenticate', authenticate);

// Register routes
app.register(authRoutes, { prefix: '/api/auth' });
// Google OAuth — manual implementation (simple-oauth2), Fastify 4 compatible
app.register(registerGoogleCallback);
app.register(assetRoutes, { prefix: '/api/assets' });
app.register(riskRoutes, { prefix: '/api/risks' });
app.register(controlRoutes, { prefix: '/api/controls' });
app.register(evidenceRoutes, { prefix: '/api/evidence' });
app.register(auditRoutes, { prefix: '/api/audits' });
app.register(userRoutes, { prefix: '/api/users' });
app.register(setupRoutes, { prefix: '/api/setup' });
app.register(policyRoutes, { prefix: '/api/policies' });

// Health check
app.get('/health', async () => {
  return { status: 'ok', timestamp: new Date().toISOString() };
});

// Error handler
app.setErrorHandler((error: any, request: any, reply: any) => {
  app.log.error(error);
  
  if (error.validation) {
    reply.status(400).send({
      error: 'Validation Error',
      message: 'Invalid request parameters',
      details: error.validation,
    });
    return;
  }

  reply.status(error.statusCode || 500).send({
    error: error.name || 'Internal Server Error',
    message: error.message || 'Something went wrong',
  });
});