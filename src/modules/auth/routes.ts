import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { authConfig } from '../../config/auth';
import { prisma } from '../../lib/prisma';
import { authenticate } from '../../lib/auth-middleware';

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(authConfig.passwordMinLength),
  name: z.string().optional(),
  role: z.enum(['SUPER_ADMIN', 'ORG_ADMIN', 'SECURITY_OWNER', 'AUDITOR', 'CONTRIBUTOR', 'VIEWER']).default('VIEWER'),
  organizationId: z.string().uuid(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

export async function authRoutes(app: FastifyInstance) {
  // Register user
  app.post('/register', async (request: any, reply: any) => {
    try {
      const data = registerSchema.parse(request.body);
      
      // Check if user already exists
      const existingUser = await prisma.user.findUnique({
        where: { email: data.email },
      });
      
      if (existingUser) {
        return reply.status(400).send({
          error: 'User already exists',
          message: 'A user with this email already registered',
        });
      }
      
      // Hash password
      const bcrypt = require('bcryptjs');
      const hashedPassword = await bcrypt.hash(data.password, authConfig.bcryptRounds);
      
      // Create user
      const user = await prisma.user.create({
        data: {
          email: data.email,
          name: data.name,
          role: data.role,
          organizationId: data.organizationId,
          password: hashedPassword,
        },
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          organizationId: true,
          createdAt: true,
        },
      });
      
      // Generate JWT
      const token = app.jwt.sign({
        sub: user.id,
        email: user.email,
        role: user.role,
        organizationId: user.organizationId,
      });
      
      return reply.status(201).send({
        user,
        token,
      });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        error: 'Registration failed',
        message: 'Failed to register user',
      });
    }
  });
  
  // Login user
  app.post('/login', async (request: any, reply: any) => {
    try {
      const data = loginSchema.parse(request.body);
      
      // Find user
      const user = await prisma.user.findUnique({
        where: { email: data.email },
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          organizationId: true,
          password: true,
          organization: true,
          createdAt: true,
        },
      });
      
      if (!user) {
        return reply.status(401).send({
          error: 'Invalid credentials',
          message: 'Email or password is incorrect',
        });
      }
      
      // Verify password
      const bcrypt = require('bcryptjs');
      const isValidPassword = await bcrypt.compare(data.password, user.password || '');
      
      if (!isValidPassword) {
        return reply.status(401).send({
          error: 'Invalid credentials',
          message: 'Email or password is incorrect',
        });
      }
      
      // Generate JWT
      const token = app.jwt.sign({
        sub: user.id,
        email: user.email,
        role: user.role,
        organizationId: user.organizationId,
      });
      
      return reply.send({
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          organizationId: user.organizationId,
          organization: user.organization,
        },
        token,
      });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        error: 'Login failed',
        message: 'Failed to authenticate user',
      });
    }
  });
  
  // Get current user (protected route)
  app.get('/me', {
    onRequest: [authenticate],
  }, async (request: any, reply: any) => {
    try {
      const userId = request.user.sub;
      
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          organizationId: true,
          createdAt: true,
        },
      });
      
      if (!user) {
        return reply.status(404).send({
          error: 'User not found',
          message: 'User account not found',
        });
      }
      
      return reply.send({ user });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        error: 'Failed to get user',
        message: 'Failed to retrieve user information',
      });
    }
  });
}