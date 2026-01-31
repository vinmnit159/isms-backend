import { FastifyRequest } from 'fastify';

export enum UserRole {
  ADMIN = 'ADMIN',
  MANAGER = 'MANAGER',
  USER = 'USER',
}

export enum Permission {
  // User management
  READ_USERS = 'read:users',
  WRITE_USERS = 'write:users',
  DELETE_USERS = 'delete:users',
  
  // Risk management
  READ_RISKS = 'read:risks',
  WRITE_RISKS = 'write:risks',
  DELETE_RISKS = 'delete:risks',
  APPROVE_RISKS = 'approve:risks',
  
  // Control management
  READ_CONTROLS = 'read:controls',
  WRITE_CONTROLS = 'write:controls',
  DELETE_CONTROLS = 'delete:controls',
  
  // Audit management
  READ_AUDITS = 'read:audits',
  WRITE_AUDITS = 'write:audits',
  
  // Evidence management
  READ_EVIDENCE = 'read:evidence',
  WRITE_EVIDENCE = 'write:evidence',
  DELETE_EVIDENCE = 'delete:evidence',
  
  // Asset management
  READ_ASSETS = 'read:assets',
  WRITE_ASSETS = 'write:assets',
  DELETE_ASSETS = 'delete:assets',
}

const rolePermissions: Record<UserRole, Permission[]> = {
  [UserRole.ADMIN]: Object.values(Permission),
  
  [UserRole.MANAGER]: [
    Permission.READ_USERS,
    Permission.READ_RISKS,
    Permission.WRITE_RISKS,
    Permission.READ_CONTROLS,
    Permission.WRITE_CONTROLS,
    Permission.READ_AUDITS,
    Permission.WRITE_AUDITS,
    Permission.READ_EVIDENCE,
    Permission.WRITE_EVIDENCE,
    Permission.READ_ASSETS,
    Permission.WRITE_ASSETS,
    Permission.APPROVE_RISKS,
  ],
  
  [UserRole.USER]: [
    Permission.READ_RISKS,
    Permission.READ_CONTROLS,
    Permission.READ_AUDITS,
    Permission.READ_EVIDENCE,
    Permission.READ_ASSETS,
    Permission.WRITE_EVIDENCE,
  ],
};

export function hasPermission(userRole: UserRole, permission: Permission): boolean {
  return rolePermissions[userRole]?.includes(permission) || false;
}

export function requirePermission(permission: Permission) {
  return async function(request: FastifyRequest) {
    const userRole = request.user?.role as UserRole;
    
    if (!userRole || !hasPermission(userRole, permission)) {
      throw new Error('Insufficient permissions');
    }
  };
}

export function requireRole(role: UserRole) {
  return async function(request: FastifyRequest) {
    const userRole = request.user?.role as UserRole;
    
    if (userRole !== role && userRole !== UserRole.ADMIN) {
      throw new Error('Insufficient role permissions');
    }
  };
}