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
