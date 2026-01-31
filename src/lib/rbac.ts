import { FastifyRequest } from 'fastify';

export enum Role {
  SUPER_ADMIN = 'SUPER_ADMIN',
  ORG_ADMIN = 'ORG_ADMIN',
  SECURITY_OWNER = 'SECURITY_OWNER',
  AUDITOR = 'AUDITOR',
  CONTRIBUTOR = 'CONTRIBUTOR',
  VIEWER = 'VIEWER',
}

export enum Permission {
  // Organization management
  READ_ORG = 'read:org',
  WRITE_ORG = 'write:org',
  MANAGE_USERS = 'manage:users',
  
  // User management
  READ_USERS = 'read:users',
  WRITE_USERS = 'write:users',
  DELETE_USERS = 'delete:users',
  
  // Asset management
  READ_ASSETS = 'read:assets',
  WRITE_ASSETS = 'write:assets',
  DELETE_ASSETS = 'delete:assets',
  
  // Risk management
  READ_RISKS = 'read:risks',
  WRITE_RISKS = 'write:risks',
  DELETE_RISKS = 'delete:risks',
  APPROVE_RISKS = 'approve:risks',
  
  // Control management
  READ_CONTROLS = 'read:controls',
  WRITE_CONTROLS = 'write:controls',
  DELETE_CONTROLS = 'delete:controls',
  
  // Evidence management
  READ_EVIDENCE = 'read:evidence',
  WRITE_EVIDENCE = 'write:evidence',
  DELETE_EVIDENCE = 'delete:evidence',
  
  // Policy management
  READ_POLICIES = 'read:policies',
  WRITE_POLICIES = 'write:policies',
  APPROVE_POLICIES = 'approve:policies',
  
  // Audit management
  READ_AUDITS = 'read:audits',
  WRITE_AUDITS = 'write:audits',
  APPROVE_AUDITS = 'approve:audits',
}

const rolePermissions: Record<Role, Permission[]> = {
  [Role.SUPER_ADMIN]: Object.values(Permission),
  
  [Role.ORG_ADMIN]: [
    Permission.READ_ORG,
    Permission.WRITE_ORG,
    Permission.MANAGE_USERS,
    Permission.READ_USERS,
    Permission.READ_ASSETS,
    Permission.WRITE_ASSETS,
    Permission.DELETE_ASSETS,
    Permission.READ_RISKS,
    Permission.WRITE_RISKS,
    Permission.DELETE_RISKS,
    Permission.READ_CONTROLS,
    Permission.WRITE_CONTROLS,
    Permission.DELETE_CONTROLS,
    Permission.READ_EVIDENCE,
    Permission.WRITE_EVIDENCE,
    Permission.DELETE_EVIDENCE,
    Permission.READ_POLICIES,
    Permission.WRITE_POLICIES,
    Permission.APPROVE_POLICIES,
    Permission.READ_AUDITS,
    Permission.WRITE_AUDITS,
    Permission.APPROVE_AUDITS,
  ],
  
  [Role.SECURITY_OWNER]: [
    Permission.READ_ASSETS,
    Permission.WRITE_ASSETS,
    Permission.READ_RISKS,
    Permission.WRITE_RISKS,
    Permission.APPROVE_RISKS,
    Permission.READ_CONTROLS,
    Permission.WRITE_CONTROLS,
    Permission.READ_EVIDENCE,
    Permission.WRITE_EVIDENCE,
    Permission.READ_POLICIES,
    Permission.WRITE_POLICIES,
    Permission.READ_AUDITS,
    Permission.WRITE_AUDITS,
  ],
  
  [Role.AUDITOR]: [
    Permission.READ_ASSETS,
    Permission.READ_RISKS,
    Permission.READ_CONTROLS,
    Permission.READ_EVIDENCE,
    Permission.WRITE_EVIDENCE,
    Permission.READ_POLICIES,
    Permission.READ_AUDITS,
    Permission.WRITE_AUDITS,
  ],
  
  [Role.CONTRIBUTOR]: [
    Permission.READ_ASSETS,
    Permission.READ_RISKS,
    Permission.WRITE_RISKS,
    Permission.READ_CONTROLS,
    Permission.WRITE_CONTROLS,
    Permission.READ_EVIDENCE,
    Permission.WRITE_EVIDENCE,
    Permission.READ_POLICIES,
    Permission.READ_AUDITS,
  ],
  
  [Role.VIEWER]: [
    Permission.READ_ASSETS,
    Permission.READ_RISKS,
    Permission.READ_CONTROLS,
    Permission.READ_EVIDENCE,
    Permission.READ_POLICIES,
    Permission.READ_AUDITS,
  ],
};

export function hasPermission(userRole: Role, permission: Permission): boolean {
  return rolePermissions[userRole]?.includes(permission) || false;
}

export function requirePermission(permission: Permission) {
  return async function(request: FastifyRequest) {
    const userRole = request.user?.role as Role;
    
    if (!userRole || !hasPermission(userRole, permission)) {
      throw new Error('Insufficient permissions');
    }
  };
}

export function requireRole(role: Role) {
  return async function(request: FastifyRequest) {
    const userRole = request.user?.role as Role;
    
    if (userRole !== role && userRole !== Role.SUPER_ADMIN) {
      throw new Error('Insufficient role permissions');
    }
  };
}