/**
 * Typed shapes for the subset of Exchange Online / Security & Compliance / Microsoft
 * Teams PowerShell data this platform consumes. Unlike src/types/graph.ts, none of this
 * comes from Microsoft Graph — it comes from a certificate-authenticated PowerShell
 * session (see src/lib/powershell). Kept in a separate file so the provenance (Graph vs.
 * PowerShell) is obvious at the type level, not just in a comment.
 */

export interface DkimConfig {
  domain: string;
  enabled: boolean;
}

export interface DmarcConfig {
  domain: string;
  /** Raw DMARC TXT record value, or null if none found. */
  record: string | null;
  policy: 'none' | 'quarantine' | 'reject' | null;
}

export interface TransportRuleSummary {
  id: string;
  name: string;
  state: 'Enabled' | 'Disabled';
  /** True if this rule auto-forwards or BCCs mail to an external recipient. */
  isExternalForwardingRule: boolean;
}

export interface RemoteDomainSummary {
  domainName: string;
  autoForwardEnabled: boolean;
}

export interface OrganizationMailConfig {
  smtpClientAuthenticationDisabled: boolean;
  auditDisabled: boolean;
}

export interface MailboxAuditBypassEntry {
  identity: string;
  auditBypassEnabled: boolean;
}

export interface SharingPolicySummary {
  id: string;
  name: string;
  /** True if calendar details are shared with any external domain ("Anonymous" or a wildcard entry). */
  sharesCalendarDetailsExternally: boolean;
}

export interface HostedContentFilterPolicySummary {
  id: string;
  name: string;
  isDefault: boolean;
  /** True if this policy applies no meaningful spam-filtering action (e.g. everything set to "no action"). */
  isEffectivelyDisabled: boolean;
}

export interface HostedConnectionFilterPolicySummary {
  id: string;
  name: string;
  ipAllowList: string[];
}

export interface AntiPhishPolicySummary {
  id: string;
  isDefault: boolean;
  enableMailboxIntelligence: boolean;
  enableSpoofIntelligence: boolean;
  enableTargetedUserProtection: boolean;
}

export interface SafeAttachmentsPolicySummary {
  id: string;
  isDefault: boolean;
  enabled: boolean;
  action: string;
}

export interface SafeLinksPolicySummary {
  id: string;
  isDefault: boolean;
  enableSafeLinksForEmail: boolean;
  enableSafeLinksForTeams: boolean;
  enableSafeLinksForOffice: boolean;
}

export interface TeamsFederationConfig {
  allowFederatedUsers: boolean;
  /** True only if federation is allowed AND unrestricted (no allow-list configured). */
  allowedDomainsIsUnrestricted: boolean;
}

export interface TeamsMeetingPolicySummary {
  id: string;
  allowAnonymousUsersToJoinMeeting: boolean;
  allowAnonymousUsersToStartMeeting: boolean;
  allowCloudRecording: boolean;
}

export interface TeamsMessagingPolicySummary {
  id: string;
  allowUserChat: boolean;
}

export interface TeamsClientConfigSummary {
  allowExternalAccess: boolean;
  allowGuestUser: boolean;
}

export interface UnifiedAuditLogConfig {
  unifiedAuditLogIngestionEnabled: boolean;
}

/**
 * Normalized bundle of everything one Exchange Online/Security & Compliance PowerShell
 * session gathers for a tenant. Collected separately from `TenantCollectionResult` (Graph)
 * since it requires a structurally different auth session — see src/lib/powershell.
 */
export interface ExoComplianceCollectionResult {
  collectedAt: string;
  dkimConfigs?: DkimConfig[];
  dmarcConfigs?: DmarcConfig[];
  transportRules?: TransportRuleSummary[];
  remoteDomains?: RemoteDomainSummary[];
  organizationMailConfig?: OrganizationMailConfig;
  mailboxAuditBypass?: MailboxAuditBypassEntry[];
  sharingPolicies?: SharingPolicySummary[];
  hostedContentFilterPolicies?: HostedContentFilterPolicySummary[];
  hostedConnectionFilterPolicies?: HostedConnectionFilterPolicySummary[];
  antiPhishPolicies?: AntiPhishPolicySummary[];
  safeAttachmentsPolicies?: SafeAttachmentsPolicySummary[];
  safeLinksPolicies?: SafeLinksPolicySummary[];
  unifiedAuditLogConfig?: UnifiedAuditLogConfig;
  errors?: Array<{ signal: string; message: string }>;
}

/** Normalized bundle of everything one Microsoft Teams PowerShell session gathers for a tenant. */
export interface TeamsCollectionResult {
  collectedAt: string;
  federationConfig?: TeamsFederationConfig;
  meetingPolicies?: TeamsMeetingPolicySummary[];
  messagingPolicies?: TeamsMessagingPolicySummary[];
  clientConfig?: TeamsClientConfigSummary;
  errors?: Array<{ signal: string; message: string }>;
}

/** Combined PowerShell-sourced signals for one collection cycle, attached onto TenantCollectionResult. */
export interface ExoTeamsSignals {
  exoCompliance?: ExoComplianceCollectionResult;
  teams?: TeamsCollectionResult;
}
