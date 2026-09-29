/**
 * Puertos (interfaces) del modulo de autenticacion.
 *
 * Por que interfaces y no llamadas directas a Drizzle
 *
 * El service de autenticacion necesita leer y escribir usuarios. Si el service
 * importara `db` directamente, no habria forma de testearlo sin levantar
 * Postgres, y las reglas de negocio (que es lo que hay que probar) quedarian
 * atadas a la infraestructura.
 *
 * Con un puerto, el test pasa un repositorio falso que devuelve lo que quiere
 * y se puede verificar la LOGICA: que un login fallido incrementa el contador,
 * que un login exitoso lo resetea, que una cuenta bloqueada no pasa. Y la
 * implementacion real con Drizzle queda en un archivo aparte, chico y sin
 * reglas dentro.
 *
 * Es el patron de puertos y adaptadores, y conviene no adorarlo: la version
 * que importa no es "usar interfaces", es que las reglas de seguridad del
 * service se puedan testear sin base de datos. Si una interface no compra eso,
 * es ceremonia de mas.
 *
 * Ver explicacion.md, seccion 33.
 */

import type { EstadoBloqueo } from './lockout.js'

/**
 * Estado de la cuenta, el `user_status` del schema.
 *
 * No es lo mismo que el bloqueo por intentos fallidos, y la confusion entre
 * ambos es un agujero de seguridad:
 *
 *   - `EstadoBloqueo` (en lockout.ts) es el bloqueo TEMPORAL por fuerza bruta.
 *     Se resuelve solo cuando pasa `lockedUntil`.
 *   - `EstadoCuenta` es el estado de la cuenta. `disabled` NO se resuelve solo:
 *     es una baja o un bloqueo que un admin tiene que levantar a mano.
 *
 * El login tiene que mirar los DOS. Con solo mirar el bloqueo temporal, una
 * cuenta dada de baja seguia permitiendo el login mientras `lockedUntil`
 * estuviera en el pasado. Por eso `status` va en `ResultadoBusqueda` y no en
 * una tabla aparte: si el service no lo recibe, no lo puede comprobar.
 */
export type EstadoCuenta = 'active' | 'locked' | 'disabled'

/** Como se busca un usuario por email. */
export type ResultadoBusqueda =
  | { encontrado: false }
  | {
      encontrado: true
      id: string
      email: string
      /** NULL para un usuario que solo se registro con Google. */
      passwordHash: string | null
      emailVerifiedAt: Date | null
      role: 'user' | 'admin'
      estado: EstadoBloqueo
      /**
       * Estado de la cuenta. Distinto de `estado` a proposito, porque son dos
       * cosas distintas que se confunden constantemente. Ver el comentario de
       * `EstadoCuenta`.
       */
      status: EstadoCuenta
    }

/** Lo que el repositorio de usuarios tiene que saber hacer. */
export interface RepositorioUsuarios {
  buscarPorEmail(email: string): Promise<ResultadoBusqueda>
  buscarPorId(id: string): Promise<ResultadoBusqueda & { encontrado: true } | null>

  crear(datos: {
    email: string
    passwordHash: string
    displayName?: string
  }): Promise<{ id: string; email: string }>

  /** Actualiza el estado de bloqueo tras un intento fallido. */
  actualizarBloqueo(id: string, estado: EstadoBloqueo): Promise<void>

  /** Limpia el estado de bloqueo tras un login exitoso. */
  limpiarBloqueo(id: string): Promise<void>

  marcarEmailVerificado(id: string, instante: Date): Promise<void>

  /**
   * Cambia la contrasena. El service pasa el hash ya calculado: hashear es
   * lento (~100 ms) y el repositorio no deberia saber de Argon2.
   */
  actualizarContrasena(id: string, passwordHash: string): Promise<void>

  /**
   * Revoca TODOS los refresh tokens del usuario.
   *
   * Existe por una sola razon, y es importante: si cambiar la contrasena no
   * colgara las sesiones abiertas, un atacante que robo la contrasena podria
   * cambiarla, expulsar al titular con un email de "tu contrasena fue cambiada"
   * y seguir dentro usando el refresh token que ya tenia. El reset de
   * contrasena sin esto no protege nada.
   *
   * Por eso es "todos" y no "los de este dispositivo".
   */
  revocarRefreshTokens(id: string, motivo: string, instante: Date): Promise<number>
}

/** Lo que el repositorio de one_time_tokens tiene que saber hacer. */
export interface RepositorioOneTimeTokens {
  /**
   * Invalida los tokens previos del mismo usuario y proposito, y guarda el
   * nuevo por su hash.
   *
   * Invalidar los anteriores es lo que hace que el ultimo email enviado sea el
   * unico valido. Sin esto, un atacante que pida un reset antes que el titular
   * conserva un token valido, y el reset legitimo del usuario no lo invalida.
   */
  guardar(params: {
    userId: string
    purpose: string
    tokenHash: string
    expiresAt: Date
  }): Promise<void>

  /** Busca por hash. Null si no existe. No filtra por `usedAt`. */
  buscarPorHash(tokenHash: string): Promise<{
    userId: string
    purpose: string
    tokenHash: string
    expiresAt: Date
    usedAt: Date | null
  } | null>

  /**
   * Marca el token como usado.
   *
   * DEBE ser condicional: el UPDATE lleva `WHERE used_at IS NULL` y se espera
   * affecte una fila. Si afecta cero, otro request ya lo canjeo y este tiene
   * que fallar. Ese es el unico modo de hacer un canje atomico sin bloqueos
   * explicitos, y evita el clasico "dos clicks en Verificar y los dos pasan".
   *
   * @returns Cuantas filas se actualizaron: 1 si se canjeo ahora, 0 si ya
   * estaba usado.
   */
  marcarUsado(params: { tokenHash: string; usadoEn: Date }): Promise<number>
}

/** Un registro de auditoria, tal como se guarda en `audit_events`. */
export interface EventoAuditoria {
  tipo: string
  userId?: string
  /** Nunca un token ni una contrasena: solo identificadores y motivos. */
  metadata?: Record<string, unknown>
  requestId?: string
  ip?: string
}

/** Donde se registran los eventos de seguridad. */
export interface RepositorioAuditoria {
  registrar(evento: EventoAuditoria): Promise<void>
}
