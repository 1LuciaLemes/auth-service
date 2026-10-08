import { errorDeCredenciales, errorInterno } from '../../lib/errors.js'
import { decidirCanje, hashearToken } from '../users/one-time-token.js'
import type {
  RepositorioAuditoria,
  RepositorioOneTimeTokens,
  RepositorioUsuarios,
} from './ports.js'

export interface DependenciasVerificacionEmail {
  usuarios: RepositorioUsuarios
  tokens: RepositorioOneTimeTokens
  auditoria: RepositorioAuditoria
}

export async function canjearVerificacionDeEmail(
  deps: DependenciasVerificacionEmail,
  token: string,
  contexto: { requestId?: string; ip?: string } = {},
): Promise<void> {
  const tokenHash = hashearToken(token)
  const fila = await deps.tokens.buscarPorHash(tokenHash)
  const veredicto = decidirCanje(fila, 'email_verification')

  if (!veredicto.ok) {
    await deps.auditoria.registrar({
      tipo: 'verificacion_fallida',
      metadata: { motivo: veredicto.motivo },
      ...contexto,
    })
    throw errorDeCredenciales('El enlace de verificacion no es valido o ya fue usado')
  }

  const canjeado = await deps.tokens.marcarUsado({ tokenHash, usadoEn: new Date() })
  if (canjeado === 0) {
    await deps.auditoria.registrar({
      tipo: 'verificacion_fallida',
      metadata: { motivo: 'canje_condicionado_ya_ocurrido' },
      ...contexto,
    })
    throw errorDeCredenciales('El enlace de verificacion no es valido o ya fue usado')
  }

  const usuario = await deps.usuarios.buscarPorId(veredicto.userId)
  if (!usuario) {
    throw errorInterno('El token de verificacion apunta a un usuario inexistente')
  }

  await deps.usuarios.marcarEmailVerificado(usuario.id, new Date())

  await deps.auditoria.registrar({
    tipo: 'email_verificado',
    userId: usuario.id,
    ...contexto,
  })
}