import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';

import { env } from './config/env';
import { jwtPlugin } from './plugins/jwt';
import { swaggerPlugin } from './plugins/swagger';
import { authRoutes } from './modules/auth/routes';
import { loggerPlugin } from './lib/logger';

export const app: FastifyInstance = Fastify({
  logger: loggerPlugin,
});

// Register plugins
app.register(helmet);
app.register(cors, {
  origin: env.CORS_ORIGIN,
  credentials: true,
});
app.register(jwtPlugin);
app.register(swaggerPlugin);

// Register routes
app.register(authRoutes, { prefix: '/api/auth' });

// Health check
app.get('/health', async () => {
  return { status: 'ok', timestamp: new Date().toISOString() };
});

// Error handler
app.setErrorHandler((error, request, reply) => {
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