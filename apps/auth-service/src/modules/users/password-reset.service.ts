/**
 * Reset de contrasena.
 *
 * Son dos operaciones separadas, y confundirlas es como se rompen estos
 * sistemas:
 *
 *   1. SOLICITAR: "he olvidado la contrasena". Responde siempre igual.
 *   2. COMPLETAR: canjear el token del email y fijar la nueva contrasena.
 *
 * Ver explicacion.md, seccion 36.
 */

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

/**
 * Unico mensaje de la solicitud de reset.
 *
 * Se devuelve SIEMPRE, exista el email o no. Si se devolviera un 404 para los
 * emails que no estan registrados, este endpoint seria un enumerador de cuentas
 * gratis: bastaria con probarlos y ver cuales dan 404.
 *
 * Y si se mandara el email solo a los que existen, un atacante podria usarlo
 * para bombardear una direccion ajena y para medir cuantos usuarios hay.
 */
export const MENSAJE_RESET_GENERICO =
  'Si esa direccion esta registrada, te enviamos un email con las instrucciones.'

export interface DependenciasReset {
  usuarios: RepositorioUsuarios
  tokens: RepositorioOneTimeTokens
  auditoria: RepositorioAuditoria
  enviarEmailDeReset: (params: { email: string; token: string; expiraEnMinutos: number }) => Promise<void>
  /** El origen para construir el link del email. Sale de APP_URL. */
  appUrl: string
}

/**
 * Paso 1: el usuario pide un reset.
 *
 * @returns Siempre `undefined`. Que no haya valor de retorno es el punto: no
 * hay nada que el endpoint pueda usar para diferenciar un caso del otro.
 */
export async function solicitarResetDeContrasena(
  deps: DependenciasReset,
  datos: { email: string },
  contexto: { requestId?: string; ip?: string } = {},
): Promise<void> {
  const email = normalizarEmail(datos.email)
  const usuario = await deps.usuarios.buscarPorEmail(email)

  if (!usuario.encontrado) {
    // Camino del email inexistente. Se registra el intento y se sale con el
    // MISMO resultado que el otro caso, sin mandar ningun email.
    //
    // El evento de auditoria se escribe en los dos caminos a proposito. Si
    // solo se escribiera cuando el email existe, el log seria un registro
    // ordenado de que emails estan en el sistema, que es exactamente el
    // oraculo que este endpoint evita darle a quien lo consulta.
    await deps.auditoria.registrar({
      tipo: 'reset_solicitado_email_inexistente',
      ...contexto,
    })
    return
  }

  // Una cuenta dada de baja no puede pedir un reset: si la activamos por el
  // camino de atrás, un admin que dio de baja a alguien vuelve a encontrarlo
  // dentro con su contrasena cambiada.
  if (usuario.status !== 'active') {
    await deps.auditoria.registrar({
      tipo: 'reset_solicitado_cuenta_no_activa',
      userId: usuario.id,
      ...contexto,
    })
    return
  }

  // El token se genera con el generador de one-time tokens, que devuelve las
  // dos mitades. A la base va el hash; al email, el token en claro.
  const emitido = generarTokenDeUnSoloUso('password_reset')

  try {
    await deps.tokens.guardar({
      userId: usuario.id,
      purpose: emitido.purpose,
      tokenHash: emitido.tokenHash,
      expiresAt: emitido.expiresAt,
    })
  } catch (error) {
    // Si no se puede guardar el token, NO se manda el email. Mandarlo sin
    // fila en la base produce un enlace que no funciona, y es peor que no
    // mandar nada: el usuario cree que tiene 15 minutos y en realidad no tiene
    // nada.
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

/**
 * Paso 2: el usuario canjea el token y fija la nueva contrasena.
 *
 * @throws AppError 401 con el MISMO mensaje para todos los fallos. Ver
 * `errorDeCredenciales`.
 */
export async function completarResetDeContrasena(
  deps: DependenciasReset,
  datos: { token: string; nuevaContrasena: string },
  contexto: { requestId?: string; ip?: string } = {},
): Promise<{ userId: string }> {
  // El token se hashea para buscarlo. La base tiene el hash, no el token: por
  // eso esta linea es la que convierte lo que llega del email en algo
  // consultable, y por eso mismo el token en claro nunca se persiste.
  const tokenHash = hashearToken(datos.token)
  const fila = await deps.tokens.buscarPorHash(tokenHash)
  const veredicto = decidirCanje(fila, 'password_reset')

  if (!veredicto.ok) {
    // Se audita el MOTIVO (token_inexistente, expirado, ya_usado) porque es
    // informacion de seguridad valiosa, pero se responde con el generico. El
    // motivo nunca sale hacia el cliente.
    await deps.auditoria.registrar({
      tipo: 'reset_fallido',
      metadata: { motivo: veredicto.motivo },
      ...contexto,
    })
    throw errorDeCredenciales()
  }

  const usuario = await deps.usuarios.buscarPorId(veredicto.userId)
  if (!usuario) {
    // El token es valido pero el usuario ya no existe. No deberia pasar, porque
    // one_time_tokens tiene ON DELETE CASCADE, asi que la fila se borra con el
    // usuario. Que llegue aqui significa borrado manual o inconsistencia, y en
    // cualquier caso no se puede dejar el token sin canjear.
    await deps.tokens.marcarUsado({ tokenHash, usadoEn: new Date() })
    throw errorDeCredenciales()
  }

  if (usuario.status !== 'active') {
    // El token se canjea tambien aqui, y no solo cuando el usuario ya no
    // existe. Es la misma situacion: un token vivo que no se puede usar hoy
    // puede servir mañana.
    //
    // Con la cuenta deshabilitada, el token sobrevive a la deshabilitacion. Si
    // un admin reactiva la cuenta dentro de la ventana de 15 minutos del token,
    // ese token vuelve a servir. Y lo hace sin que nadie lo haya pedido: el
    // email con el enlace lleva rato en la bandeja de un atacante.
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
    // 400, no 401: el token va bien, lo que esta mal es la contrasena. Y con la
    // lista de problemas, porque el usuario tiene que saber que le falta. Un
    // error generico aqui lo deja probando contrasenas al azar.
    throw errorDeValidacion('La contrasena no cumple la politica', {
      problemas: validacion.problemas,
    })
  }

  const nuevoHash = await hashearContrasena(datos.nuevaContrasena)

  // EL PASO QUE SE OLVIDA EN LA MAYORIA DE IMPLEMENTACIONES.
  //
  // Se canjea el token de forma CONDICIONAL y se comprueba que afecto una fila.
  // Si affecto cero, otro request lo canjeo primero y este tiene que fallar.
  //
  // Sin la comprobacion del cero, dos clicks en "Verificar" en el mismo
  // instante, o un atacante y el titular a la vez, permiten los dos canjear el
  // mismo token: uno pone la contrasena y el otro pone la que quiere, y el
  // atacante gana aunque la respuesta que vea el titular sea un exito.
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

  // Se limpia el bloqueo por intentos fallidos. Si no, el contador de la
  // contrasena antigua sigue ahi y el titular que acaba de recuperar su cuenta
  // podria quedarse bloqueado por intentos que el ATACANTE fue los que hizo.
  await deps.usuarios.limpiarBloqueo(usuario.id)

  // Y se cuelgan las sesiones abiertas. Sin esto, el reset no protege nada:
  // el atacante que robo la contrasena la cambia, recibe el aviso por email,
  // y sigue dentro con su refresh token porque nada lo invalido.
  const revocados = await deps.usuarios.revocarRefreshTokens(
    usuario.id,
    'password_reset',
    new Date(),
  )

  await deps.auditoria.registrar({
    tipo: 'reset_exitoso',
    userId: usuario.id,
    // Solo el NUMERO de sesiones revocadas, nunca los identificadores de los
    // tokens: esos son material de autenticacion.
    metadata: { sesionesRevocadas: revocados },
    ...contexto,
  })

  return { userId: usuario.id }
}
