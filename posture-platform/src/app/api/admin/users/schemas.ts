/**
 * Zod schemas for the admin user-management API surface (src/app/api/admin/users).
 * Kept separate from the route handlers so both the API routes and the admin
 * UI/server actions can share the exact same validation, mirroring the
 * convention in src/app/api/tenants/schemas.ts.
 */

import { z } from 'zod';

/** Mirrors the Prisma UserRole enum / Role type in src/lib/auth/types.ts. */
export const roleSchema = z.enum(['SUPER_ADMIN', 'ANALYST', 'CUSTOMER_VIEWER']);

/** Prisma cuid()-generated ids. */
export const cuidSchema = z
  .string()
  .trim()
  .regex(/^c[a-z0-9]{20,}$/i, 'Must be a valid id.');

export const createUserSchema = z.object({
  email: z.string().trim().toLowerCase().email().max(320),
  name: z.string().trim().min(1).max(200).optional(),
  role: roleSchema,
  /**
   * Only meaningful when role === 'CUSTOMER_VIEWER'. Tenant ids (within the
   * admin's own organization) to grant TenantAccess to as part of the same
   * create operation. Ignored for SUPER_ADMIN/ANALYST roles, which do not use
   * TenantAccess.
   */
  tenantIds: z.array(cuidSchema).max(500).optional(),
});
export type CreateUserInput = z.infer<typeof createUserSchema>;

export const updateUserSchema = z
  .object({
    role: roleSchema.optional(),
    isActive: z.boolean().optional(),
    name: z.string().trim().min(1).max(200).nullable().optional(),
  })
  .refine((data) => data.role !== undefined || data.isActive !== undefined || data.name !== undefined, {
    message: 'At least one of role, isActive, or name must be provided.',
  });
export type UpdateUserInput = z.infer<typeof updateUserSchema>;

export const tenantAccessActionSchema = z.object({
  tenantId: cuidSchema,
});
export type TenantAccessActionInput = z.infer<typeof tenantAccessActionSchema>;
