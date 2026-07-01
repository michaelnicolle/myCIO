export { authOptions } from './options';
export {
  requireRole,
  getAuthorizedSession,
  getAccessibleTenantIds,
  canAccessTenant,
  isRole,
  UnauthenticatedError,
  ForbiddenError,
} from './rbac';
export type { Role, AuthorizedSession } from './rbac';
