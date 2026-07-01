import { redirect } from 'next/navigation';

/**
 * The tenant list itself lives at /overview (MSP-wide view of every tenant's
 * latest score + open finding counts). This route exists only so the
 * sidebar's "Tenants" nav item has a stable, non-dynamic URL to link to
 * rather than requiring a specific tenantId up front.
 */
export default function TenantsIndexPage() {
  redirect('/overview');
}
