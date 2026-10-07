

import {
  errorDeConflicto,
  errorDeCredenciales,
  errorDeValidacion,
  errorInterno,
} from '../../lib/errors.js'
import { hashearContrasena, verificarContrasena, verificarContraReferencia } from '../../lib/password.js'
import { normalizarEmail } from '../../lib/crypto.js'
import { validarContrasena } from '../../lib/password-policy.js'
import {
  decidirSiPermitido,
  mensajeDeCredencialesInvalidas,
  registrarIntentoExitoso,
  registrarIntentoFallido,
  type EstadoBloqueo,
  type PoliticaBloqueo,
} from './lockout.js'
import type { RepositorioAuditoria, RepositorioUsuarios } from './ports.js'


export interface ResultadoLogin {
  userId: string
  email: string
  emailVerificado: boolean
}


export interface DependenciasAuth {
  usuarios: RepositorioUsuarios
  auditoria: RepositorioAuditoria
  politica: PoliticaBloqueo

  generarTokenDeVerificacion: (
    userId: string,
  ) => Promise<{ token: string; tokenHash: string; expira: Date }>

  enviarEmailDeVerificacion: (params: { email: string; token: string }) => Promise<void>
}


export async function registrarUsuario(
  deps: DependenciasAuth,
  datos: { email: string; contrasena: string; displayName?: string },
  contexto: { requestId?: string; ip?: string } = {},
): Promise<{ userId: string; email: string }> {
  const email = normalizarEmail(datos.email)




  const validacion = validarContrasena(datos.contrasena)
  if (!validacion.valida) {


    throw errorDeValidacion('La contrasena no cumple la politica', {
      problemas: validacion.problemas,
    })
  }

  const existente = await deps.usuarios.buscarPorEmail(email)
  if (existente.encontrado) {
    await deps.auditoria.registrar({
      tipo: 'registro_rechazado_email_duplicado',
      userId: existente.id,
      ...contexto,
    })
    throw errorDeConflicto('Ya existe una cuenta con ese email')
  }

  const hash = await hashearContrasena(datos.contrasena)

  let creado: { id: string; email: string }
  try {
    creado = await deps.usuarios.crear({ email, passwordHash: hash, displayName: datos.displayName })
  } catch (error) {









    if (esViolacionDeUnicidad(error)) {
      await deps.auditoria.registrar({
        tipo: 'registro_rechazado_email_duplicado',
        ...contexto,
      })
      throw errorDeConflicto('Ya existe una cuenta con ese email')
    }


    throw errorInterno('No se pudo crear la cuenta', {
      causa: error instanceof Error ? error.message : 'desconocida',
    })
  }

  const verificacion = await deps.generarTokenDeVerificacion(creado.id)







  await deps.enviarEmailDeVerificacion({ email: creado.email, token: verificacion.token })

  await deps.auditoria.registrar({
    tipo: 'registro_exitoso',
    userId: creado.id,
    ...contexto,
  })





  return { userId: creado.id, email: creado.email }
}


function esViolacionDeUnicidad(error: unknown): boolean {


  if (typeof error !== 'object' || error === null) return false



  const codigo = (error as { code?: unknown }).code
  if (codigo === '23505') return true





  const constraint = (error as { constraint?: unknown }).constraint
  return typeof constraint === 'string' && constraint.includes('email')
}


export async function iniciarSesion(
  deps: DependenciasAuth,
  datos: { email: string; contrasena: string },
  ahora: Date,
  contexto: { requestId?: string; ip?: string } = {},
): Promise<ResultadoLogin> {
  const email = normalizarEmail(datos.email)
  const usuario = await deps.usuarios.buscarPorEmail(email)







  if (!usuario.encontrado) {
    await verificarContraReferencia(datos.contrasena)

    await deps.auditoria.registrar({
      tipo: 'login_fallido_usuario_inexistente',


      metadata: { motivo: 'usuario_inexistente' },
      ...contexto,
    })

    throw errorDeCredenciales()
  }






  const decision = decidirSiPermitido(usuario.estado, deps.politica, ahora)
  if (!decision.permitido) {
    await deps.auditoria.registrar({
      tipo: 'login_bloqueado',
      userId: usuario.id,
      metadata: { minutosRestantes: decision.minutosRestantes },
      ...contexto,
    })

    throw errorDeCredenciales()
  }







  if (usuario.passwordHash === null) {
    await deps.auditoria.registrar({
      tipo: 'login_fallido_sin_contrasena',
      userId: usuario.id,
      ...contexto,
    })

    throw errorDeCredenciales()
  }














  const contrasenaCorrecta = await verificarContrasena(usuario.passwordHash, datos.contrasena)

  if (!contrasenaCorrecta) {
    const nuevoEstado = registrarIntentoFallido(usuario.estado, deps.politica, ahora)
    await deps.usuarios.actualizarBloqueo(usuario.id, nuevoEstado.estado)

    await deps.auditoria.registrar({
      tipo: 'login_fallido',
      userId: usuario.id,



      metadata: {
        intentosRestantes: Math.max(0, deps.politica.maxIntentos - nuevoEstado.estado.intentosFallidos),
        seBloqueo: nuevoEstado.seBloqueo,
      },
      ...contexto,
    })

    const decisionPosterior = decidirSiPermitido(
      nuevoEstado.estado,
      deps.politica,
      ahora,
    )
    const restantes = decisionPosterior.permitido ? decisionPosterior.intentosRestantes : 0

    throw errorDeCredenciales(mensajeDeCredencialesInvalidas(restantes))
  }


















  if (usuario.status !== 'active') {
    await deps.auditoria.registrar({
      tipo: 'login_cuenta_no_activa',
      userId: usuario.id,


      metadata: { status: usuario.status },
      ...contexto,
    })

    throw errorDeCredenciales()
  }






  await deps.usuarios.limpiarBloqueo(usuario.id)

  await deps.auditoria.registrar({
    tipo: 'login_exitoso',
    userId: usuario.id,
    ...contexto,
  })

  return {
    userId: usuario.id,
    email: usuario.email,
    emailVerificado: usuario.emailVerifiedAt !== null,
  }
}


export async function verificarEmail(
  deps: DependenciasAuth,
  userId: string,
  instante: Date,
  contexto: { requestId?: string; ip?: string } = {},
): Promise<void> {
  const usuario = await deps.usuarios.buscarPorId(userId)

  if (!usuario) {



    throw errorInterno('El token de verificacion apunta a un usuario inexistente')
  }



  if (usuario.emailVerifiedAt !== null) {
    return
  }

  await deps.usuarios.marcarEmailVerificado(userId, instante)

  await deps.auditoria.registrar({
    tipo: 'email_verificado',
    userId,
    ...contexto,
  })
}


export function estadoDeBloqueoParaElCliente(estado: EstadoBloqueo, ahora: Date): {
  bloqueado: boolean
  minutosRestantes: number
} {
  if (estado.bloqueadaHasta !== null && estado.bloqueadaHasta.getTime() > ahora.getTime()) {
    return {
      bloqueado: true,
      minutosRestantes: Math.max(
        1,
        Math.ceil((estado.bloqueadaHasta.getTime() - ahora.getTime()) / 60_000),
      ),
    }
  }

  return { bloqueado: false, minutosRestantes: 0 }
}
