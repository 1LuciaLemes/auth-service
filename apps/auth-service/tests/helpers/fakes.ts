import type {
  EventoAuditoria,
  RepositorioAuditoria,
  RepositorioOneTimeTokens,
  RepositorioUsuarios,
  ResultadoBusqueda,
  EstadoCuenta,
} from '../../src/modules/auth/ports.js'
import type { EstadoBloqueo, PoliticaBloqueo } from '../../src/modules/auth/lockout.js'
import type { TokenAlmacenado } from '../../src/modules/users/one-time-token.js'

export const POLITICA_DEFAULT: PoliticaBloqueo = { maxIntentos: 5, minutosDeBloqueo: 15 }

export interface UsuarioEnMemoria {
  id: string
  email: string
  passwordHash: string | null
  emailVerifiedAt: Date | null
  role: 'user' | 'admin'
  estado: EstadoBloqueo
  status: EstadoCuenta
}

export interface EmailsCapturados {
  deVerificacion: Array<{ email: string; token: string }>
  deReset: Array<{ email: string; token: string; expiraEnMinutos: number }>
}

export interface FakesDeMemoria {
  usuarios: RepositorioUsuarios
  tokens: RepositorioOneTimeTokens
  auditoria: RepositorioAuditoria
  emails: EmailsCapturados
  usuariosInternos: Map<string, UsuarioEnMemoria>
  tokensInternos: Map<string, TokenAlmacenado>
  eventos: EventoAuditoria[]
}

export function crearFakesDeMemoria(): FakesDeMemoria {
  const porEmail = new Map<string, UsuarioEnMemoria>()
  const tokensInternos = new Map<string, TokenAlmacenado>()
  const eventos: EventoAuditoria[] = []
  const emails: EmailsCapturados = { deVerificacion: [], deReset: [] }
  let siguienteId = 1

  const usuarios: RepositorioUsuarios = {
    async buscarPorEmail(email): Promise<ResultadoBusqueda> {
      const usuario = porEmail.get(email)
      if (!usuario) return { encontrado: false }
      return {
        encontrado: true,
        id: usuario.id,
        email: usuario.email,
        passwordHash: usuario.passwordHash,
        emailVerifiedAt: usuario.emailVerifiedAt,
        role: usuario.role,
        estado: { ...usuario.estado },
        status: usuario.status,
      }
    },

    async buscarPorId(id) {
      for (const usuario of porEmail.values()) {
        if (usuario.id !== id) continue
        return {
          encontrado: true,
          id: usuario.id,
          email: usuario.email,
          passwordHash: usuario.passwordHash,
          emailVerifiedAt: usuario.emailVerifiedAt,
          role: usuario.role,
          estado: { ...usuario.estado },
          status: usuario.status,
        }
      }
      return null
    },

    async crear({ email, passwordHash, displayName }) {
      void displayName
      const usuario: UsuarioEnMemoria = {
        id: `usr_${siguienteId++}`,
        email,
        passwordHash,
        emailVerifiedAt: null,
        role: 'user',
        estado: { intentosFallidos: 0, bloqueadaHasta: null },
        status: 'active',
      }
      porEmail.set(email, usuario)
      return { id: usuario.id, email: usuario.email }
    },

    async actualizarBloqueo(id, estado) {
      for (const usuario of porEmail.values()) {
        if (usuario.id === id) usuario.estado = { ...estado }
      }
    },

    async limpiarBloqueo(id) {
      for (const usuario of porEmail.values()) {
        if (usuario.id === id) {
          usuario.estado = { intentosFallidos: 0, bloqueadaHasta: null }
        }
      }
    },

    async marcarEmailVerificado(id, instante) {
      for (const usuario of porEmail.values()) {
        if (usuario.id === id) usuario.emailVerifiedAt = instante
      }
    },

    async actualizarContrasena(id, passwordHash) {
      for (const usuario of porEmail.values()) {
        if (usuario.id === id) usuario.passwordHash = passwordHash
      }
    },

    async revocarRefreshTokens() {
      return 0
    },
  }

  const tokens: RepositorioOneTimeTokens = {
    async guardar({ userId, purpose, tokenHash, expiresAt }) {
      tokensInternos.set(tokenHash, { userId, purpose, tokenHash, expiresAt, usedAt: null })
    },

    async buscarPorHash(tokenHash) {
      const fila = tokensInternos.get(tokenHash)
      return fila ? { ...fila } : null
    },

    async marcarUsado({ tokenHash, usadoEn }) {
      const fila = tokensInternos.get(tokenHash)
      if (!fila || fila.usedAt !== null) return 0
      fila.usedAt = usadoEn
      return 1
    },
  }

  const auditoria: RepositorioAuditoria = {
    async registrar(evento: EventoAuditoria) {
      eventos.push(evento)
    },
  }

  return {
    usuarios,
    tokens,
    auditoria,
    emails,
    usuariosInternos: porEmail,
    tokensInternos,
    eventos,
  }
}