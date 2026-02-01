import Fastify, { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';

import { env } from './config/env';
import { jwtPlugin } from './plugins/jwt';
import { swaggerPlugin } from './plugins/swagger';
import { authenticate } from './lib/auth-middleware';
import { authRoutes } from './modules/auth/routes';
import { assetRoutes } from './modules/assets/routes';
import { riskRoutes } from './modules/risks/routes';
import { controlRoutes } from './modules/controls/routes';
import { evidenceRoutes } from './modules/evidence/routes';
import { auditRoutes } from './modules/audits/routes';
import { userRoutes } from './modules/users/routes';

export const app: FastifyInstance = Fastify({
  logger: {
    level: env.LOG_LEVEL,
  },
});

// Register plugins
app.register(helmet);
app.register(cors, {
  origin: env.CORS_ORIGIN,
  credentials: true,
});
app.register(jwtPlugin);
app.register(swaggerPlugin);

// Add authentication decorator
app.decorate('authenticate', authenticate);

// Register routes
app.register(authRoutes, { prefix: '/api/auth' });
app.register(assetRoutes, { prefix: '/api/assets' });
app.register(riskRoutes, { prefix: '/api/risks' });
app.register(controlRoutes, { prefix: '/api/controls' });
app.register(evidenceRoutes, { prefix: '/api/evidence' });
app.register(auditRoutes, { prefix: '/api/audits' });
app.register(userRoutes, { prefix: '/api/users' });

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