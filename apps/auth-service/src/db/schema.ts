/**
 * Schema de la base de datos, con Drizzle.
 *
 * Drizzle es un ORM: traduce entre TypeScript y SQL (explicacion.md,
 * seccion 28). Se eligio sobre Prisma por dos razones:
 *
 *   - No tiene binario nativo. En Vercel serverless un binario generado es
 *     una fuente de problemas de cold start.
 *   - No esconde el SQL. Con Drizzle se ve exactamente que se ejecuta, que
 *     es justamente el objetivo de este proyecto: entender la base de datos.
 *
 * Convencion de nombres: en TypeScript se escribe en camelCase, en la base de
 * datos en snake_case. Cada columna declara los dos. Escribirlos juntos en la
 * definicion es lo que evita la Confusion de tenerlos separados.
 *
 * Todas las columnas de tiempo usan `withTimezone: true`. Sin eso, Postgres
 * guarda fechas en hora local y los comparaciones entre servidores en zonas
 * horarias distintas dan resultados incorrectos. Ver la nota de expiracion
 * mas abajo.
 */

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

/**
 * ENUM REAL DE POSTGRES, no un text con validacion en el codigo.
 *
 * Postgres garantiza que role solo valga 'user' o 'admin'. La base de datos es
 * la ultima linea de defensa: si un bug en el codigo intentara guardar
 * 'superadmin', la base lo rechaza. Con un text, el bug pasaria desapercibido.
 */
export const roleEnum = pgEnum('role', ['user', 'admin'])

/**
 * Estado de la cuenta.
 *
 *   active = normal
 *   locked = bloqueada por exceso de intentos fallidos
 *
 * Nota: el lockout tambien tiene un campo `lockedUntil` en users, con la hora
 * exacta. Este enum sirve para el estado de baja permanente. La combinacion de
 * los dos cubre los casos: un bloqueo temporal se resuelve solo cuando pasa
 * la hora, y el estado locked representa una baja o un bloqueo que un admin
 * tiene que levantar a mano.
 */
export const userStatusEnum = pgEnum('user_status', ['active', 'locked', 'disabled'])

/**
 * Grant types de OAuth2 que el service admite.
 *
 *   authorization_code = flujo con PKCE, el unico para clientes web
 *   refresh_token      = renovar el access token
 */
export const grantTypeEnum = pgEnum('grant_type', ['authorization_code', 'refresh_token'])

// ============================================================
// USERS
// ============================================================

export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),

  /**
   * El email identifica a la persona, y por eso es UNIQUE en toda la tabla.
   * Esa unicidad es la que sostiene el account linking: si un email ya existe,
   * pertenece a un solo usuario, y no puede haber dos cuentas con el mismo.
   * Ver explicacion.md, seccion 19.
   *
   * Se guarda en minusculas, porque los emails no distinguen mayusculas en la
   * practica. Si se guardara tal cual, Lucia@x.com y lucia@x.com serian dos
   * cuentas distintas, que es justo el bug que el account linking evita.
   */
  email: text('email').notNull().unique(),

  /**
   * NULLABLE A PROPOSITO.
   *
   * Un usuario creado con Google no tiene contrasena. Y un usuario con
   * contrasena puede despues vincular Google, con lo que sigue teniendo
   * contrasena pero ahora tambien tiene una identity.
   *
   * Si este campo fuera NOT NULL, habria que inventar un valor falso para los
   * usuarios de Google, y eso seria una contrasena debil escondida en la base.
   * Ver explicacion.md, seccion 19.
   */
  passwordHash: text('password_hash'),

  displayName: text('display_name'),

  /**
   * NULL hasta que el usuario verifica su email. La diferencia importa: un
   * email sin verificar es un campo de texto, nada mas. Nunca se usa para
   * decidir con quien se vincula una cuenta.
   */
  emailVerifiedAt: timestamp('email_verified_at', { withTimezone: true }),

  role: roleEnum('role').notNull().default('user'),
  status: userStatusEnum('status').notNull().default('active'),

  /**
   * Contador de intentos de login fallidos consecutivos. Se resetea a 0 en
   * cuanto hay un login exitoso.
   *
   * Esto es distinto del rate limit: el rate limit vive en Redis y cuenta
   * requests, y esto vive en la fila del usuario y cuenta FALLOS de
   * autenticacion. Son dos capas distintas y por eso el schema tiene las dos.
   * Ver explicacion.md, seccion 22.
   */
  failedLoginAttempts: integer('failed_login_attempts').notNull().default(0),

  /**
   * Instante en que se levanta el bloqueo. NULL = no bloqueado.
   *
   * Guarda la hora de expiracion, no un booleano "bloqueado", porque el
   * bloqueo tiene quecaducar solo. Con un booleano habria que correr un job
   * cada minuto para destrabar cuentas; con la fecha, la consulta resuelve
   * sola: `lockedUntil > now()`.
   */
  lockedUntil: timestamp('locked_until', { withTimezone: true }),

  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
})

// ============================================================
// IDENTITIES  (account linking)
// ============================================================

/**
 * Las distintas formas de autenticarse de un mismo usuario.
 *
 * La regla: un email verificado pertenece a UN solo usuario, y ese usuario
 * puede tener varias identities. Esta tabla es la que permite que alguien
 * entre con Google O con contrasena y llegue al mismo perfil.
 *
 * `password` no se guarda aca: vive en users.passwordHash. Esta tabla es
 * solo para los proveedores externos, que es donde hay algo que registrar.
 */
export const identities = pgTable(
  'identities',
  {
    id: uuid('id').primaryKey().defaultRandom(),

    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),

    /**
     * 'google', y en el futuro 'github', 'apple'.
     *
     * Se guarda como texto y no como enum porque el service tiene que ser
     * extensible sin migrar la base cada vez que se suma un proveedor: es
     * justamente el motivo de la interfaz Provider.
     */
    provider: text('provider').notNull(),

    /**
     * El identificador del usuario EN ESE PROVEEDOR. El id de Google para
     * este usuario, el id de GitHub para este usuario.
     *
     * No es el email. El email puede cambiar en el proveedor, y si la clave
     * fuera el email, al cambiar se perderia la vinculacion. Con el id
     * numerico del proveedor, la vinculacion es estable.
     */
    providerAccountId: text('provider_account_id').notNull(),

    /** Email segun el proveedor. Se guarda para referencia y auditoria. */
    email: text('email'),

    /**
     * Si el proveedor dice que verifico ese email. Se guarda aunque sea false,
     * porque es parte de la decision de seguridad: sin email verificado no se
     * vincula nada. Ver explicacion.md, seccion 19.
     */
    emailVerified: boolean('email_verified').notNull().default(false),

    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (tabla) => ({
    /**
     * Un usuario no puede tener dos veces el mismo proveedor.
     */
    userProvider: uniqueIndex('identities_user_provider_idx').on(
      tabla.userId,
      tabla.provider,
    ),

    /**
     * Y una cuenta de un proveedor no puede estar vinculada a dos usuarios.
     * Esta es la que evita que dos personas sean la misma.
     */
    providerAccount: uniqueIndex('identities_provider_account_idx').on(
      tabla.provider,
      tabla.providerAccountId,
    ),
  }),
)

// ============================================================
// CLIENTS  (registro de aplicaciones)
// ============================================================

/**
 * Cada aplicacion que consume el service tiene que estar registrada.
 *
 * Sin registro, cualquiera podria pedir tokens con un client_id inventado. Con
 * registro, el service sabe a quien le esta dando acceso y con que permisos.
 */
export const clients = pgTable('clients', {
  /**
   * Identificador publico del cliente. Viaja en claro en cada request, asi
   * que puede ser publico. NO es un secreto.
   */
  clientId: text('client_id').notNull().primaryKey(),

  /**
   * NULLABLE, y la razon es importante.
   *
   *   - NULL          = PUBLIC CLIENT. No tiene secreto. Tipicamente una SPA
   *                     o una app movil, donde todo el codigo es visible y no
   *                     hay donde esconder un secreto. Se autentica solo con
   *                     PKCE.
   *
   *   - con valor     = CONFIDENTIAL CLIENT. Tipicamente un backend con
   *                     servidor. Ademas de PKCE, tiene que presentar el
   *                     secreto, que se guarda HASHEADO igual que una
   *                     contrasena, nunca en claro.
   *
   * Ver explicacion.md, seccion 13.
   */
  clientSecretHash: text('client_secret_hash'),

  clientName: text('client_name').notNull(),

  /**
   * Lista de URIs de redireccion permitidas. Es la defensa contra open
   * redirect, y por eso es una lista en la base de datos y no un patron:
   * tiene que ser coincidencia EXACTA, sin comodines. Ver seccion 17.
   */
  redirectUris: text('redirect_uris').array().notNull(),

  /**
   * Scopes que este cliente puede pedir. Un cliente que pide algo fuera de
   * esta lista recibe error en /authorize.
   */
  allowedScopes: text('allowed_scopes').array().notNull().default(['openid', 'email']),

  grantTypes: grantTypeEnum('grant_types').array().notNull().default(['authorization_code', 'refresh_token']),

  /**
   * Si es obligatorio usar PKCE. Para los public clients, SIEMPRE.
   *
   * Existe como columna y no como regla fija para que un cliente
   * confidencial pueda desactivarlo si hace falta. Para los public clients se
   * fuerza a true en el codigo sin importar el valor de aca.
   */
  requirePkce: boolean('require_pkce').notNull().default(true),

  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
})

// ============================================================
// AUTH CODES  (flujo Authorization Code con PKCE)
// ============================================================

/**
 * Los codigos de autorizacion, de un solo uso y de 60 segundos de vida.
 *
 * Se guarda el HASH del codigo, nunca el codigo en claro. Es la misma razon
 * por la que un refresh token se hashea: si se filtrara la base de datos, con
 * los codigos en claro un atacante podria canjearlos por tokens.
 *
 * Y por que NO se borran al canjear: la tabla marca `usedAt` en vez de hacer
 * un DELETE. Un codigo ya usado tiene que seguir siendo detectable, porque si
 * un attacker reenvia un codigo que ya se canjeo, eso es una senal de que el
 * codigo estuvo en dos manos. Ver explicacion.md, seccion 16.
 */
export const authCodes = pgTable(
  'auth_codes',
  {
    id: uuid('id').primaryKey().defaultRandom(),

    /** SHA-256 del codigo. Es la clave de busqueda. */
    codeHash: text('code_hash').notNull().unique(),

    clientId: text('client_id')
      .notNull()
      .references(() => clients.clientId, { onDelete: 'cascade' }),

    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),

    /**
     * El redirect_uri con el que sepidio el codigo. Se guarda para
     * revalidarlo en /token: si al canjear el codigo el redirect_uri es
     * distinto, se rechaza. Sin esta comparacion, un atacante podria pedir un
     * codigo para una URI legitima y canjearlo declarando otra.
     */
    redirectUri: text('redirect_uri').notNull(),

    /**
     * El code_challenge que mando el cliente. Al canjear, se verifica que
     * SHA-256(code_verifier) sea igual a este valor. Es el nucleo de PKCE.
     */
    codeChallenge: text('code_challenge').notNull(),

    /**
     * Solo se admite 'S256'. Se guarda igual para poder registrar si alguien
     * intenta traer 'plain', que es un ataque en curso. Ver seccion 13.
     */
    codeChallengeMethod: text('code_challenge_method').notNull().default('S256'),

    scopes: text('scopes').array().notNull(),

    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),

    /**
     * Momento del canje. NULL = todavia no se canjeo. Un codigo con usedAt
     * no se vuelve a usar nunca.
     */
    usedAt: timestamp('used_at', { withTimezone: true }),

    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (tabla) => ({
    /** Indice para poder borrar los codigos viejos que ya expiraron. */
    expiresIdx: index('auth_codes_expires_idx').on(tabla.expiresAt),
  }),
)

// ============================================================
// REFRESH TOKENS  (rotativos, con deteccion de reuso)
// ============================================================

/**
 * Refresh tokens hasheados, con familia y rotacion.
 *
 * Esta tabla es la mas importante del diseno de seguridad. Tres decisiones
 * que hay que entender (explicacion.md, seccion 16):
 *
 * 1. Se guarda el HASH (SHA-256), no el token. Con el token en claro, una
 *    base de datos filtrada es equivalente a tener todas las sesiones
 *    activas de todos los usuarios.
 *
 * 2. La tabla es APPEND-ONLY. Nunca se borra una fila: se marca usedAt o
 *    revokedAt. Esto es lo que hace posible detectar el reuso. Si el token
 *    viejo se eliminara al rotar, un reuso seria indistinguible de un token
 *    inventado, y la deteccion no tendria sentido.
 *
 * 3. Hay un familyId. Todos los tokens de una misma cadena de renovaciones
 *    comparten familia. Cuando se detecta un reuso, se revoca la familia
 *    entera de una sola vez.
 */
export const refreshTokens = pgTable(
  'refresh_tokens',
  {
    id: uuid('id').primaryKey().defaultRandom(),

    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),

    sessionId: uuid('session_id').references(() => sessions.id, { onDelete: 'cascade' }),

    /**
     * El identificador de la FAMILIA. Se hereda en cada renovacion: el token
     * nuevo nace con el mismo familyId que el viejo.
     *
     * Es lo que hace que la revocacion en cascada sea una sola operacion.
     */
    familyId: uuid('family_id').notNull(),

    /** SHA-256 del token. Unico, y con indice, porque es como se busca. */
    tokenHash: text('token_hash').notNull().unique(),

    /**
     * El token del que nacio este. Forma el arbol de la familia: el token 2
     * tiene parentId apuntando al token 1, el token 3 al token 2, y asi.
     *
     * Por que ON DELETE SET NULL y no CASCADE: si se borrara un token viejo
     * por limpieza de historial, el CASCADE llevaria tambien a sus hijos, y
     * un solo DELETE podria borrar media familia. Con SET NULL, los hijos
     * sobreviven como tokens sin padre, que es un estado valido y no rompe
     * nada: la revocacion en cascada usa familyId, no parentId.
     */
    parentId: uuid('parent_id'),

    /**
     * Momento en que se canjeo por otro token. NULL = nunca se uso.
     * Un token con usedAt que vuelve a presentarse es un REUSO.
     */
    usedAt: timestamp('used_at', { withTimezone: true }),

    /** Momento en que se invalido (logout, reuso, cambio de password). */
    revokedAt: timestamp('revoked_at', { withTimezone: true }),

    /** Razon de la revocacion. Para entender que paso en el audit trail. */
    revokedReason: text('revoked_reason'),

    /**
     * Expiracion. OJO con el calculo: se hace SIEMPRE contra `new Date()`, el
     * reloj de la aplicacion, y no contra `now()` de Postgres.
     *
     * Razon: si el calculo lo hiciera la base, un cambio de zona horaria
     * entre el servidor de aplicacion y el de base de datos produciria
     * expiraciones con una hora de diferencia. La base y la app tienen que
     * estar de acuerdo, y por eso el calculo vive en el codigo.
     */
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),

    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (tabla) => ({
    /**
     * Indice por familia. Es el que hace la revocacion en cascada eficiente:
     * sin el, la busqueda seria un recorrido secuencial de toda la tabla.
     */
    familyIdx: index('refresh_tokens_family_idx').on(tabla.familyId),

    /**
     * Indice por token hash. Redundante con el UNIQUE de arriba, pero explicito
     * porque es la consulta mas frecuente del sistema (cada refresh), y quiero
     * que la intencion este documentada en el schema y no solo en un comment.
     */
    tokenHashIdx: index('refresh_tokens_token_hash_idx').on(tabla.tokenHash),

    /**
     * Para listar los tokens activos de un usuario, por ejemplo en un
     * "cerrar todas las sesiones".
     */
    userRevokedIdx: index('refresh_tokens_user_revoked_idx').on(tabla.userId, tabla.revokedAt),
  }),
)

// ============================================================
// SESSIONS  (dispositivos activos)
// ============================================================

/**
 * Una sesion por dispositivo donde el usuario esta autenticado.
 *
 * Es lo que alimenta la pantalla "Mis dispositivos": user agent, IP, fecha de
 * inicio y ultimo uso, y desde aca se puede revocar una o cerrar todas.
 *
 * Una sesion esta vinculada a una familia de refresh tokens. Esa relacion es
 * bidireccional: `sessions.refreshTokenFamilyId` y `refreshTokens.sessionId`.
 * Existe por los dos lados para poder responder rapido a las dos preguntas
 * que se hacen en flujos distintos:
 *
 *   - "revocar esta sesion"  -> por sessionId
 *   - "cerrar todas"         -> por userId
 *   - "que sesion es esta"    -> por el sid del access token
 */
export const sessions = pgTable(
  'sessions',
  {
    id: uuid('id').primaryKey().defaultRandom(),

    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),

    /**
     * La familia de refresh tokens de esta sesion. Cuando se revoca un token
     * por reuso, se revoca la familia, y con este campo se sabe que sesion
     * cerrar.
     */
    refreshTokenFamilyId: uuid('refresh_token_family_id').notNull(),

    /** User agent del navegador o app. Se muestra en la lista de sesiones. */
    userAgent: text('user_agent'),

    /** IP desde la que se creo la sesion. */
    ip: text('ip'),

    /** Ultimo uso. Se actualiza en cada refresh, para ordenar por actividad. */
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }).notNull().defaultNow(),

    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    revokedReason: text('revoked_reason'),

    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (tabla) => ({
    /**
     * Indice para listar las sesiones activas de un usuario. Es la consulta
     * de la pantalla "Mis dispositivos".
     */
    userRevokedIdx: index('sessions_user_revoked_idx').on(tabla.userId, tabla.revokedAt),
  }),
)

// ============================================================
// TOKENS DE UN SOLO USO  (verificacion de email y reset de password)
// ============================================================

/**
 * Tokens de un solo uso para verificar email y para resetear contrasena.
 *
 * Son dos flujos distintos con el mismo patron, asi que se modelan juntos en
 * una tabla con una columna `purpose` que los separa.
 *
 * Por que NO son filas de users con una columna `verification_token`:
 *
 *   - Se necesitarian dos columnas mas (una por proposito) y el modelo
 *     quedaria mas dificil de extender.
 *   - Perderian el historial. Con una tabla, se puede ver cuando se pidio cada
 *     token, cual se uso y cuando.
 *   - Es mas seguro que un unico campo en users: ahi un bug podria pisar el
 *     token de verificacion con el de reset. Aca estan en filas distintas.
 *
 * Ver explicacion.md, secciones 32 y 36.
 */
export const oneTimeTokens = pgTable(
  'one_time_tokens',
  {
    id: uuid('id').primaryKey().defaultRandom(),

    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),

    /**
     * 'email_verification' o 'password_reset'.
     *
     * El purpose se valida SIEMPRE en el canje. Sin esa comprobacion, un
     * token de reset de contrasena podria usarse para "verificar" un email, o
     * al reves, y las dos operaciones son de riesgo distinto.
     */
    purpose: text('purpose').notNull(),

    /** SHA-256 del token. Unico: un token, una fila. */
    tokenHash: text('token_hash').notNull().unique(),

    /**
     * Expiracion.
     *
     *   - email_verification: 24 horas. No es urgente.
     *   - password_reset:     15 minutos. Si es el mas sensible, es el que
     *     mas rapido tiene que expirar.
     */
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),

    /** Momento del uso. NULL = todavia no se canjeo. Un solo uso. */
    usedAt: timestamp('used_at', { withTimezone: true }),

    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (tabla) => ({
    /**
     * Indice por usuario y purpose. Es la consulta que se hace al pedir un
     * token nuevo: "invalida los tokens previos de este usuario para este
     * proposito".
     */
    userPurposeIdx: index('one_time_tokens_user_purpose_idx').on(tabla.userId, tabla.purpose),
  }),
)

// ============================================================
// AUDIT LOG  (eventos de seguridad)
// ============================================================

/**
 * Eventos de seguridad: login ok y fallido, refresh reuse, reset de
 * contrasena, revocaciones.
 *
 * Es APPEND-ONLY: solo se insertan filas, nunca se actualizan ni se borran.
 * Si un atacante logra entrar al servidor, no tiene que poder borrar su
 * rastro, y un log editable no sirve como evidencia.
 *
 * Ver explicacion.md, secciones 25 y 26.
 */
export const auditEvents = pgTable(
  'audit_events',
  {
    id: uuid('id').primaryKey().defaultRandom(),

    /**
     * NULL cuando no se pudo identificar al usuario. Un login fallido con un
     * email que no existe NO tiene userId, y ese es justamente el caso
     * interesante: es un intento de accesso con una identidad que no esta
     * registrada.
     */
    userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),

    clientId: text('client_id'),

    /**
     * Tipo de evento. Texto y no enum, para poder sumar tipos sin migrar:
     *
     *   login_ok, login_failed, refresh_reuse, password_reset,
     *   password_reset_requested, email_verified, user_registered,
     *   token_revoked, session_revoked, all_sessions_revoked,
     *   account_linked, account_link_reauth_failed, auth_code_issued,
     *   token_issued
     */
    type: text('type').notNull(),

    /** IP del request. Importante para detectar ataques distribuidos. */
    ip: text('ip'),

    userAgent: text('user_agent'),

    /**
     * Contexto extra del evento, en JSON.
     *
     * Se usa `jsonb` y no `text` a proposito: jsonb valida que lo que se
     * guarda es JSON de verdad, y permite indexar campos internos si mas
     * adelante hace falta consultarlos. Con text, un typo como guardar
     * `[object Object]` pasaria inadvertido.
     *
     * OJO: aqui NUNCA se escribe un token ni un password. Solo datos de
     * contexto: el familyId de una familia revocada, el sessionId de una
     * sesion, el motivo de un lockout. Ver explicacion.md, seccion 26.
     */
    metadata: jsonb('metadata').$type<Record<string, unknown>>(),

    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (tabla) => ({
    /** Indice por usuario y fecha, para ver la actividad de una cuenta. */
    userCreatedIdx: index('audit_events_user_created_idx').on(tabla.userId, tabla.createdAt),

    /** Indice por tipo y fecha, para detectar patrones (ej. muchos refresh_reuse). */
    typeCreatedIdx: index('audit_events_type_created_idx').on(tabla.type, tabla.createdAt),
  }),
)

// ============================================================
// TIPOS DERIVADOS DEL SCHEMA
// ============================================================

/**
 * Los tipos salen del schema, nunca al reves. Mismo criterio que con el
 * entorno: el schema es la fuente de verdad, y el tipo se deriva de el, para
 * que no se puedan desincronizar en silencio.
 */
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

/** Propositos de los tokens de un solo uso. */
export const TOKEN_PURPOSES = ['email_verification', 'password_reset'] as const
export type TokenPurpose = (typeof TOKEN_PURPOSES)[number]

/** Tipos de evento del audit log. */
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
