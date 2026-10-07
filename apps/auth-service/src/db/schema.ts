

import {
  boolean,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core'


export const roleEnum = pgEnum('role', ['user', 'admin'])


export const userStatusEnum = pgEnum('user_status', ['active', 'locked', 'disabled'])


export const grantTypeEnum = pgEnum('grant_type', ['authorization_code', 'refresh_token'])





export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),


  email: text('email').notNull().unique(),


  passwordHash: text('password_hash'),

  displayName: text('display_name'),


  emailVerifiedAt: timestamp('email_verified_at', { withTimezone: true }),

  role: roleEnum('role').notNull().default('user'),
  status: userStatusEnum('status').notNull().default('active'),


  failedLoginAttempts: integer('failed_login_attempts').notNull().default(0),


  lockedUntil: timestamp('locked_until', { withTimezone: true }),

  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
})






export const identities = pgTable(
  'identities',
  {
    id: uuid('id').primaryKey().defaultRandom(),

    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),


    provider: text('provider').notNull(),


    providerAccountId: text('provider_account_id').notNull(),


    email: text('email'),


    emailVerified: boolean('email_verified').notNull().default(false),

    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (tabla) => ({

    userProvider: uniqueIndex('identities_user_provider_idx').on(
      tabla.userId,
      tabla.provider,
    ),


    providerAccount: uniqueIndex('identities_provider_account_idx').on(
      tabla.provider,
      tabla.providerAccountId,
    ),
  }),
)






export const clients = pgTable('clients', {

  clientId: text('client_id').notNull().primaryKey(),


  clientSecretHash: text('client_secret_hash'),

  clientName: text('client_name').notNull(),


  redirectUris: text('redirect_uris').array().notNull(),


  allowedScopes: text('allowed_scopes').array().notNull().default(['openid', 'email']),

  grantTypes: grantTypeEnum('grant_types').array().notNull().default(['authorization_code', 'refresh_token']),


  requirePkce: boolean('require_pkce').notNull().default(true),

  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
})






export const authCodes = pgTable(
  'auth_codes',
  {
    id: uuid('id').primaryKey().defaultRandom(),


    codeHash: text('code_hash').notNull().unique(),

    clientId: text('client_id')
      .notNull()
      .references(() => clients.clientId, { onDelete: 'cascade' }),

    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),


    redirectUri: text('redirect_uri').notNull(),


    codeChallenge: text('code_challenge').notNull(),


    codeChallengeMethod: text('code_challenge_method').notNull().default('S256'),

    scopes: text('scopes').array().notNull(),

    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),


    usedAt: timestamp('used_at', { withTimezone: true }),

    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (tabla) => ({

    expiresIdx: index('auth_codes_expires_idx').on(tabla.expiresAt),
  }),
)






export const refreshTokens = pgTable(
  'refresh_tokens',
  {
    id: uuid('id').primaryKey().defaultRandom(),

    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),

    sessionId: uuid('session_id').references(() => sessions.id, { onDelete: 'cascade' }),


    familyId: uuid('family_id').notNull(),


    tokenHash: text('token_hash').notNull().unique(),


    parentId: uuid('parent_id'),


    usedAt: timestamp('used_at', { withTimezone: true }),


    revokedAt: timestamp('revoked_at', { withTimezone: true }),


    revokedReason: text('revoked_reason'),


    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),

    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (tabla) => ({

    familyIdx: index('refresh_tokens_family_idx').on(tabla.familyId),


    tokenHashIdx: index('refresh_tokens_token_hash_idx').on(tabla.tokenHash),


    userRevokedIdx: index('refresh_tokens_user_revoked_idx').on(tabla.userId, tabla.revokedAt),
  }),
)






export const sessions = pgTable(
  'sessions',
  {
    id: uuid('id').primaryKey().defaultRandom(),

    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),


    refreshTokenFamilyId: uuid('refresh_token_family_id').notNull(),


    userAgent: text('user_agent'),


    ip: text('ip'),


    lastUsedAt: timestamp('last_used_at', { withTimezone: true }).notNull().defaultNow(),

    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    revokedReason: text('revoked_reason'),

    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (tabla) => ({

    userRevokedIdx: index('sessions_user_revoked_idx').on(tabla.userId, tabla.revokedAt),
  }),
)






export const oneTimeTokens = pgTable(
  'one_time_tokens',
  {
    id: uuid('id').primaryKey().defaultRandom(),

    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),


    purpose: text('purpose').notNull(),


    tokenHash: text('token_hash').notNull().unique(),


    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),


    usedAt: timestamp('used_at', { withTimezone: true }),

    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (tabla) => ({

    userPurposeIdx: index('one_time_tokens_user_purpose_idx').on(tabla.userId, tabla.purpose),
  }),
)






export const auditEvents = pgTable(
  'audit_events',
  {
    id: uuid('id').primaryKey().defaultRandom(),


    userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),

    clientId: text('client_id'),


    type: text('type').notNull(),


    ip: text('ip'),

    userAgent: text('user_agent'),


    metadata: jsonb('metadata').$type<Record<string, unknown>>(),

    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (tabla) => ({

    userCreatedIdx: index('audit_events_user_created_idx').on(tabla.userId, tabla.createdAt),


    typeCreatedIdx: index('audit_events_type_created_idx').on(tabla.type, tabla.createdAt),
  }),
)






export type User = typeof users.$inferSelect
export type NewUser = typeof users.$inferInsert

export type Identity = typeof identities.$inferSelect
export type NewIdentity = typeof identities.$inferInsert

export type Client = typeof clients.$inferSelect
export type NewClient = typeof clients.$inferInsert

export type AuthCode = typeof authCodes.$inferSelect
export type NewAuthCode = typeof authCodes.$inferInsert

export type RefreshToken = typeof refreshTokens.$inferSelect
export type NewRefreshToken = typeof refreshTokens.$inferInsert

export type Session = typeof sessions.$inferSelect
export type NewSession = typeof sessions.$inferInsert

export type OneTimeToken = typeof oneTimeTokens.$inferSelect
export type NewOneTimeToken = typeof oneTimeTokens.$inferInsert

export type AuditEvent = typeof auditEvents.$inferSelect
export type NewAuditEvent = typeof auditEvents.$inferInsert

export type Role = (typeof roleEnum.enumValues)[number]
export type UserStatus = (typeof userStatusEnum.enumValues)[number]
export type GrantType = (typeof grantTypeEnum.enumValues)[number]


export const TOKEN_PURPOSES = ['email_verification', 'password_reset'] as const
export type TokenPurpose = (typeof TOKEN_PURPOSES)[number]


export const AUDIT_EVENT_TYPES = [
  'user_registered',
  'email_verified',
  'login_ok',
  'login_failed',
  'refresh_reuse',
  'password_reset',
  'password_reset_requested',
  'token_revoked',
  'session_revoked',
  'all_sessions_revoked',
  'account_linked',
  'account_link_reauth_failed',
  'auth_code_issued',
  'token_issued',
] as const
export type AuditEventType = (typeof AUDIT_EVENT_TYPES)[number]
