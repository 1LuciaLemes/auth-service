

import type { EstadoBloqueo } from './lockout.js'


export type EstadoCuenta = 'active' | 'locked' | 'disabled'


export type ResultadoBusqueda =
  | { encontrado: false }
  | {
      encontrado: true
      id: string
      email: string

      passwordHash: string | null
      emailVerifiedAt: Date | null
      role: 'user' | 'admin'
      estado: EstadoBloqueo

      status: EstadoCuenta
    }


export interface RepositorioUsuarios {
  buscarPorEmail(email: string): Promise<ResultadoBusqueda>
  buscarPorId(id: string): Promise<ResultadoBusqueda & { encontrado: true } | null>

  crear(datos: {
    email: string
    passwordHash: string
    displayName?: string
  }): Promise<{ id: string; email: string }>


  actualizarBloqueo(id: string, estado: EstadoBloqueo): Promise<void>


  limpiarBloqueo(id: string): Promise<void>

  marcarEmailVerificado(id: string, instante: Date): Promise<void>


  actualizarContrasena(id: string, passwordHash: string): Promise<void>


  revocarRefreshTokens(id: string, motivo: string, instante: Date): Promise<number>
}


export interface RepositorioOneTimeTokens {

  guardar(params: {
    userId: string
    purpose: string
    tokenHash: string
    expiresAt: Date
  }): Promise<void>


  buscarPorHash(tokenHash: string): Promise<{
    userId: string
    purpose: string
    tokenHash: string
    expiresAt: Date
    usedAt: Date | null
  } | null>


  marcarUsado(params: { tokenHash: string; usadoEn: Date }): Promise<number>
}


export interface EventoAuditoria {
  tipo: string
  userId?: string

  metadata?: Record<string, unknown>
  requestId?: string
  ip?: string
}


export interface RepositorioAuditoria {
  registrar(evento: EventoAuditoria): Promise<void>
}
