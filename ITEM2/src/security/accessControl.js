const permissions = Object.freeze({
  admin: new Set(['users:read:any', 'users:manage', 'orders:create', 'orders:read:any', 'loyalty:read:any']),
  support: new Set(['users:read:any', 'orders:read:any']),
  customer: new Set(['users:read:own', 'orders:create', 'loyalty:read:own'])
});

export const ROLES = Object.freeze({
  ADMIN: 'admin',
  SUPPORT: 'support',
  CUSTOMER: 'customer'
});

export function assertPermission(actor, permission, resourceUserId) {
  if (!actor?.role || !permissions[actor.role]) {
    throw new Error('Acceso denegado. Rol no válido.');
  }

  const allowed = permissions[actor.role];
  if (allowed.has(permission)) return true;

  if (permission.endsWith(':own') && actor.userId === resourceUserId) {
    return allowed.has(permission);
  }

  throw new Error('Acceso denegado. No tiene permisos para esta operación.');
}

export function ownerActor(userId) {
  return { userId, role: ROLES.CUSTOMER };
}

export function permissionsForRole(role) {
  return [...(permissions[role] ?? [])];
}