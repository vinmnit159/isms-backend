import jwt from '@fastify/jwt';
import { FastifyInstance } from 'fastify';
import { env } from '../config/env';

export async function jwtPlugin(app: FastifyInstance) {
  app.register(jwt, {
    secret: env.JWT_SECRET,
    sign: {
      expiresIn: env.JWT_EXPIRES_IN,
    },
  });
}

// Declare JWT payload type
declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: {
      sub: string;
      email: string;
      role: string;
      organizationId: string;
    };
    user: {
      id: string;
      email: string;
      role: string;
      organizationId: string;
    };
  }
}