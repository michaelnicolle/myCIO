export { authOptions } from './options';
export {
  requireRole,
  getAuthorizedSession,
  isRole,
  UnauthenticatedError,
  ForbiddenError,
} from './rbac';
export type { Role, AuthorizedSession } from './rbac';
