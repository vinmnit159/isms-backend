import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { prisma } from '../../lib/prisma';
import { Role, AssetType, RiskLevel } from '../../lib/rbac';
import { seedDatabase } from '../../lib/seed';
import { authConfig } from '../../config/auth';

const signupWithOrganizationSchema = z.object({
  organizationName: z.string().min(2, 'Organization name must be at least 2 characters'),
  adminName: z.string().min(2, 'Admin name must be at least 2 characters'),
  adminEmail: z.string().email('Invalid email format'),
  adminPassword: z.string()
    .min(authConfig.passwordMinLength, `Password must be at least ${authConfig.passwordMinLength} characters`)
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
  orgAdminName: z.string().min(2, 'Org admin name must be at least 2 characters'),
  orgAdminEmail: z.string().email('Invalid email format'),
  orgAdminPassword: z.string()
    .min(authConfig.passwordMinLength, `Password must be at least ${authConfig.passwordMinLength} characters`)
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
});

export async function setupRoutes(app: FastifyInstance) {
  // Sign up with organization setup
  app.post('/setup', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const data = signupWithOrganizationSchema.parse(request.body);
      
      // Check if any users already exist
      const existingUser = await prisma.user.findFirst();
      if (existingUser) {
        return reply.status(400).send({
          error: 'System already initialized',
          message: 'The system has already been set up. Please contact your administrator.',
        });
      }

      // Check for duplicate emails (case insensitive)
      const existingAdminEmail = await prisma.user.findFirst({
        where: { email: data.adminEmail.toLowerCase() }
      });
      const existingOrgAdminEmail = await prisma.user.findFirst({
        where: { email: data.orgAdminEmail.toLowerCase() }
      });
      
      if (existingAdminEmail || existingOrgAdminEmail) {
        return reply.status(400).send({
          error: 'Duplicate email',
          message: 'Email address already exists. Please use a different email.',
        });
      }
      if (existingUser) {
        return reply.status(400).send({
          error: 'System already initialized',
          message: 'The system has already been set up. Please contact your administrator.',
        });
      }

      // 1. Create Organization
      const organization = await prisma.organization.create({
        data: {
          name: data.organizationName,
        },
      });

      // 2. Create SUPER_ADMIN user
      const hashedSuperAdminPassword = await bcrypt.hash(data.adminPassword, authConfig.bcryptRounds);
      const superAdmin = await prisma.user.create({
        data: {
          email: data.adminEmail.toLowerCase(),
          password: hashedSuperAdminPassword,
          name: data.adminName,
          role: Role.SUPER_ADMIN,
          organizationId: organization.id,
        },
      });

      // 3. Create ORG_ADMIN user
      const hashedOrgAdminPassword = await bcrypt.hash(data.orgAdminPassword, authConfig.bcryptRounds);
      const orgAdmin = await prisma.user.create({
        data: {
          email: data.orgAdminEmail.toLowerCase(),
          password: hashedOrgAdminPassword,
          name: data.orgAdminName,
          role: Role.ORG_ADMIN,
          organizationId: organization.id,
        },
      });

      // 4. Seed ISO controls for the organization
      try {
        await seedDatabase(prisma);
        console.log('✅ Database seeded successfully');
      } catch (seedError) {
        console.error('❌ Database seeding failed:', seedError);
        return reply.status(500).send({
          error: 'Database seeding failed',
          message: 'Failed to seed ISO controls and policies',
        });
      }

      // Verify users were created successfully before generating JWT
      if (!superAdmin || !superAdmin.id || !orgAdmin || !orgAdmin.id) {
        return reply.status(500).send({
          error: 'User creation failed',
          message: 'Failed to create admin users',
        });
      }

      console.log('✅ Users created:', { 
        superAdmin: { id: superAdmin.id, email: superAdmin.email },
        orgAdmin: { id: orgAdmin.id, email: orgAdmin.email }
      });

      // Generate JWT token for super admin
      const token = app.jwt.sign({
        sub: superAdmin.id,
        email: superAdmin.email,
        role: superAdmin.role,
        organizationId: superAdmin.organizationId,
      });
      console.log('✅ JWT token generated for:', superAdmin.email);

      // Log the setup activity
      await prisma.activityLog.create({
        data: {
          userId: superAdmin.id,
          action: 'SYSTEM_SETUP',
          entity: 'ORGANIZATION',
          entityId: organization.id,
        },
      });

      return reply.status(201).send({
        success: true,
        message: 'Organization and users created successfully',
        data: {
          organization: {
            id: organization.id,
            name: organization.name,
            createdAt: organization.createdAt,
          },
          superAdmin: {
            id: superAdmin.id,
            email: superAdmin.email,
            name: superAdmin.name,
            role: superAdmin.role,
          },
          orgAdmin: {
            id: orgAdmin.id,
            email: orgAdmin.email,
            name: orgAdmin.name,
            role: orgAdmin.role,
          },
          token,
          setupComplete: true,
        },
      });

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.error('Setup error details:', {
        message: errorMessage,
        stack: error instanceof Error ? error.stack : 'No stack trace',
        code: (error as any)?.code,
        type: (error.constructor as any)?.name || 'Unknown'
      });
      
      const prismaError = error as any;
      if (prismaError?.code === 'P2002') {
        return reply.status(400).send({
          error: 'Duplicate entry',
          message: 'An organization or user with this information already exists',
        });
      }

      return reply.status(500).send({
        error: 'Setup failed',
        message: `Failed to set up organization and users: ${errorMessage}`,
      });
    }
  });

  // Check system setup status
  app.get('/setup-status', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const userCount = await prisma.user.count();
      const organizationCount = await prisma.organization.count();
      
      return reply.send({
        setup: userCount > 0,
        userCount,
        organizationCount,
        canSetup: userCount === 0 && organizationCount === 0,
      });
    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        error: 'Status check failed',
        message: 'Failed to check setup status',
      });
    }
  });

  // Reset system (for development/testing)
  app.post('/reset-system', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      // This endpoint should only be available in development
      if (process.env.NODE_ENV === 'production') {
        return reply.status(403).send({
          error: 'Forbidden',
          message: 'System reset is not allowed in production',
        });
      }

      // Delete all data in order (due to foreign key constraints)
      await prisma.auditFinding.deleteMany({});
      await prisma.evidence.deleteMany({});
      await prisma.audit.deleteMany({});
      await prisma.riskTreatment.deleteMany({});
      await prisma.risk.deleteMany({});
      await prisma.control.deleteMany({});
      await prisma.policy.deleteMany({});
      await prisma.user.deleteMany({});
      await prisma.asset.deleteMany({});
      await prisma.organization.deleteMany({});

      return reply.send({
        success: true,
        message: 'System reset successfully',
      });

    } catch (error) {
      app.log.error(error);
      return reply.status(500).send({
        error: 'Reset failed',
        message: 'Failed to reset system',
      });
    }
  });
}