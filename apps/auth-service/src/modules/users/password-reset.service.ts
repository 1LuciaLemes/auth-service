

import { normalizarEmail } from '../../lib/crypto.js'
import { validarContrasena } from '../../lib/password-policy.js'
import { hashearContrasena } from '../../lib/password.js'
import { errorDeCredenciales, errorDeValidacion, errorInterno } from '../../lib/errors.js'
import { decidirCanje, generarTokenDeUnSoloUso, hashearToken } from '../users/one-time-token.js'
import type {
  RepositorioAuditoria,
  RepositorioOneTimeTokens,
  RepositorioUsuarios,
} from '../auth/ports.js'


export const MENSAJE_RESET_GENERICO =
  'Si esa direccion esta registrada, te enviamos un email con las instrucciones.'

export interface DependenciasReset {
  usuarios: RepositorioUsuarios
  tokens: RepositorioOneTimeTokens
  auditoria: RepositorioAuditoria
  enviarEmailDeReset: (params: { email: string; token: string; expiraEnMinutos: number }) => Promise<void>

  appUrl: string
}


export async function solicitarResetDeContrasena(
  deps: DependenciasReset,
  datos: { email: string },
  contexto: { requestId?: string; ip?: string } = {},
): Promise<void> {
  const email = normalizarEmail(datos.email)
  const usuario = await deps.usuarios.buscarPorEmail(email)

  if (!usuario.encontrado) {







    await deps.auditoria.registrar({
      tipo: 'reset_solicitado_email_inexistente',
      ...contexto,
    })
    return
  }




  if (usuario.status !== 'active') {
    await deps.auditoria.registrar({
      tipo: 'reset_solicitado_cuenta_no_activa',
      userId: usuario.id,
      ...contexto,
    })
    return
  }



  const emitido = generarTokenDeUnSoloUso('password_reset')

  try {
    await deps.tokens.guardar({
      userId: usuario.id,
      purpose: emitido.purpose,
      tokenHash: emitido.tokenHash,
      expiresAt: emitido.expiresAt,
    })
  } catch (error) {




    throw errorInterno('No se pudo iniciar el proceso de reset', {
      causa: error instanceof Error ? error.message : 'desconocida',
    })
  }

  await deps.enviarEmailDeReset({
    email: usuario.email,
    token: emitido.token,
    expiraEnMinutos: 15,
  })

  await deps.auditoria.registrar({
    tipo: 'reset_solicitado',
    userId: usuario.id,
    ...contexto,
  })
}


export async function completarResetDeContrasena(
  deps: DependenciasReset,
  datos: { token: string; nuevaContrasena: string },
  contexto: { requestId?: string; ip?: string } = {},
): Promise<{ userId: string }> {



  const tokenHash = hashearToken(datos.token)
  const fila = await deps.tokens.buscarPorHash(tokenHash)
  const veredicto = decidirCanje(fila, 'password_reset')

  if (!veredicto.ok) {



    await deps.auditoria.registrar({
      tipo: 'reset_fallido',
      metadata: { motivo: veredicto.motivo },
      ...contexto,
    })
    throw errorDeCredenciales()
  }

  const usuario = await deps.usuarios.buscarPorId(veredicto.userId)
  if (!usuario) {




    await deps.tokens.marcarUsado({ tokenHash, usadoEn: new Date() })
    throw errorDeCredenciales()
  }

  if (usuario.status !== 'active') {








    await deps.tokens.marcarUsado({ tokenHash, usadoEn: new Date() })
    await deps.auditoria.registrar({
      tipo: 'reset_fallido',
      userId: usuario.id,
      metadata: { motivo: 'cuenta_no_activa' },
      ...contexto,
    })
    throw errorDeCredenciales()
  }

  const validacion = validarContrasena(datos.nuevaContrasena)
  if (!validacion.valida) {



    throw errorDeValidacion('La contrasena no cumple la politica', {
      problemas: validacion.problemas,
    })
  }

  const nuevoHash = await hashearContrasena(datos.nuevaContrasena)










  const canjeado = await deps.tokens.marcarUsado({ tokenHash, usadoEn: new Date() })
  if (canjeado === 0) {
    await deps.auditoria.registrar({
      tipo: 'reset_fallido',
      userId: usuario.id,
      metadata: { motivo: 'canje_condicionado_ya_ocurrido' },
      ...contexto,
    })
    throw errorDeCredenciales()
  }

  await deps.usuarios.actualizarContrasena(usuario.id, nuevoHash)




  await deps.usuarios.limpiarBloqueo(usuario.id)




  const revocados = await deps.usuarios.revocarRefreshTokens(
    usuario.id,
    'password_reset',
    new Date(),
  )

  await deps.auditoria.registrar({
    tipo: 'reset_exitoso',
    userId: usuario.id,


    metadata: { sesionesRevocadas: revocados },
    ...contexto,
  })

  return { userId: usuario.id }
}
