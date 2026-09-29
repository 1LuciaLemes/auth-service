/**
 * Servicio de autenticacion: registro, login y verificacion de email.
 *
 * Toda la logica de seguridad vive aca y es testeable sin base de datos,
 * porque el repositorio entra por parametro. Las tres reglas que gobiernan este
 * archivo:
 *
 *   1. El login NO dice si el email existe.
 *   2. El login tarda lo mismo exista o no la cuenta.
 *   3. Un email sin verificar no sirve para nada importante.
 *
 * Ver explicacion.md, secciones 19, 22 y 23.
 */

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

/** Lo que devuelve un login exitoso. */
export interface ResultadoLogin {
  userId: string
  email: string
  emailVerificado: boolean
}

/** Dependencias del servicio. */
export interface DependenciasAuth {
  usuarios: RepositorioUsuarios
  auditoria: RepositorioAuditoria
  politica: PoliticaBloqueo
  /**
   * Genera el token de verificacion de email. Se inyecta para que el test
   * pueda poner un valor conocido y no depender de la aleatoriedad.
   *
   * Devuelve LAS DOS MITADES a proposito, y no solo una:
   *
   *   - `token`: el valor en claro. Va SOLO al email y se descarta.
   *   - `tokenHash`: SHA-256. Va SOLO a la base.
   *
   * Si esta interfaz devolviera un unico campo, el error natural seria
   * persistirlo y mandarlo a los dos lados, o mandarlo a los dos, y cualquiera
   * de las dos cosas rompe el sistema en silencio. Ver explicacion.md, seccion 32.
   */
  generarTokenDeVerificacion: (
    userId: string,
  ) => Promise<{ token: string; tokenHash: string; expira: Date }>
  /**
   * Envia el email. Se inyecta por la misma razon, y tambien para que el
   * registro funcione en tests sin llamar a Resend de verdad.
   */
  enviarEmailDeVerificacion: (params: { email: string; token: string }) => Promise<void>
}

/**
 * Registra un usuario con email y contrasena.
 *
 * DECISION DE DISENO QUE PARECE MALA Y NO LO ES: si el email ya existe, se
 * devuelve 409 con un mensaje explicito.
 *
 * Lo ideal en teoria seria responder 201 con un email generico de "si esta
 * registrado, te mandamos un correo", para no revelar que emails estan dados de
 * alta. Se eligio NO hacerlo a proposito, y la razon es que ese patron rompe la
 * usabilidad sin olvidar la seguridad:
 *
 * - El usuario que intenta registrarse con un email ya usado recibe un exito
 *   y no puede entrar. Prueba de nuevo, recibe exito otra vez, y en tres
 *   intentos tiene una cuenta abandonada y ninguna pista de por que.
 * - El mensaje generico obliga al sitio a ADVERTIR que casi siempre significa
 *   que el email ya existe, y esa advertencia es el mensaje real.
 *
 * Con 409 el mensaje es util de verdad. Y el ataque que evita, enumerar
 * emails, no es el principal: para eso el login es generico, y el atacante
 * que quiere saber si TU email esta registrado ya puede intentar el login.
 *
 * Lo que si se hace, y es lo importante: el endpoint de login nunca dice si el
 * email existe. Aca, en el registro, se acepta el trade-off.
 */
export async function registrarUsuario(
  deps: DependenciasAuth,
  datos: { email: string; contrasena: string; displayName?: string },
  contexto: { requestId?: string; ip?: string } = {},
): Promise<{ userId: string; email: string }> {
  const email = normalizarEmail(datos.email)

  // La politica se aplica ANTES de hashear. Hashear con argon2 cuesta ~100 ms y
  // 19 MB, asi que rechazar una contrasena debil despues de hashear desperdicia
  // justo el recurso que se usa para frenar ataques de fuerza bruta.
  const validacion = validarContrasena(datos.contrasena)
  if (!validacion.valida) {
    // 400 con la lista de problemas, no un error generico: el usuario tiene que
    // saber que le falta, porque si no esta probando contrasenas al azar.
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
    // Carrera entre dos registros simultaneos con el mismo email: los dos
    // pasan el buscarPorEmail y uno gana el INSERT. El UNIQUE de la base lo
    // rechaza, y sin este catch el usuario veria un 500 en vez de un 409.
    //
    // Lo que se NECESITA es distinguir esa violacion de un fallo real. En un
    // `catch` que convierte cualquier error en 500, un corte de red tambien
    // devolvia 'Ya existe una cuenta con ese email', que es un diagnostico
    // falso: el usuario reintenta, el email sigue libre, y el error se repite
    // hasta que creye que el problema es suyo.
    if (esViolacionDeUnicidad(error)) {
      await deps.auditoria.registrar({
        tipo: 'registro_rechazado_email_duplicado',
        ...contexto,
      })
      throw errorDeConflicto('Ya existe una cuenta con ese email')
    }

    // Cualquier otro error es nuestro, no del usuario: 500 generico.
    throw errorInterno('No se pudo crear la cuenta', {
      causa: error instanceof Error ? error.message : 'desconocida',
    })
  }

  const verificacion = await deps.generarTokenDeVerificacion(creado.id)

  // OJO, aqui hay una distincion que no se puede invertir: al email va el
  // `token` EN CLARO y a la base ya fue el `tokenHash`. Mandar el hash
  // (que fue lo que hacia este modulo) produce un enlace de verificacion
  // inservible: el usuario lo abre, el endpoint hashea el hash que recibe y
  // busca ese hash en la base, donde esta el hash DEL HASH, y nunca coincide.
  // El bug es invisible porque el registro devuelve 201 y el email sale bien.
  await deps.enviarEmailDeVerificacion({ email: creado.email, token: verificacion.token })

  await deps.auditoria.registrar({
    tipo: 'registro_exitoso',
    userId: creado.id,
    ...contexto,
  })

  // Se devuelve `userId` y no `id` a proposito: el service no deberia filtrar
  // el nombre de la columna de la base hacia el endpoint. Es una mania, pero
  // asi el dia de mañana cambiar `id` por `user_id` en el schema no obliga a
  // tocar el contrato de la API.
  return { userId: creado.id, email: creado.email }
}

/**
 * Detecta una violacion de la restriccion UNIQUE de PostgreSQL.
 *
 * PostgreSQL reporta el conflicto con el codigo '23505' (unique_violation), y
 * el nombre de la constraint en `constraint`. Se mira el codigo y no el texto
 * del mensaje: el mensaje esta en ingles, cambia entre versiones y lo cambia
 * el traductor si alguien pone la base en otro idioma. Comparar textos para
 * decidir el status HTTP es la forma habitual de que un endpoint devuelva 500
 * cuando deberia devolver 409, solo en unos pocos casos, y solo en produccion.
 */
function esViolacionDeUnicidad(error: unknown): boolean {
  // `unknown` y no `Error`: el catch de TypeScript entrega cualquier cosa, y
  // presuponer que es un Error obliga a hacer un cast que es mentira.
  if (typeof error !== 'object' || error === null) return false

  // Se mira `code` porque es el campo estable del driver `pg` para el
  // SQLSTATE de la base.
  const codigo = (error as { code?: unknown }).code
  if (codigo === '23505') return true

  // Fallback por nombre de constraint. Se acepta `email` porque es la
  // constraint de `users`, que es la unica que puede saltar en este INSERT.
  // Aceptar CUALQUIER 23505 a secas seria un error: la misma clase de error
  // aparece por otros motivos que no significan 'email duplicado'.
  const constraint = (error as { constraint?: unknown }).constraint
  return typeof constraint === 'string' && constraint.includes('email')
}

/**
 * Autentica a un usuario con email y contrasena.
 *
 * ACa esta el nucleo de la seguridad del login, y son cuatro pasos en un orden
 * que importa mucho.
 *
 * @throws AppError 401 SIEMPRE en caso de fallo, sin decir cual fue el motivo.
 */
export async function iniciarSesion(
  deps: DependenciasAuth,
  datos: { email: string; contrasena: string },
  ahora: Date,
  contexto: { requestId?: string; ip?: string } = {},
): Promise<ResultadoLogin> {
  const email = normalizarEmail(datos.email)
  const usuario = await deps.usuarios.buscarPorEmail(email)

  // --- PASO 1: si la cuenta no existe, se responde igual de rápido ----------
  //
  // `verificarContraReferencia` corre un argon2 contra un hash fijo. Sin esto,
  // el caso "no existe" tarda 2 ms y el caso "existe, contrasena mala" tarda
  // 100 ms, y esa diferencia de 98 ms es suficiente para enumerar toda la base
  // de emails con un simple reloj.
  if (!usuario.encontrado) {
    await verificarContraReferencia(datos.contrasena)

    await deps.auditoria.registrar({
      tipo: 'login_fallido_usuario_inexistente',
      // OJO: no se manda el email al audit log. El log lo lee gente con menos
      // permiso que la base, y un email es un dato personal.
      metadata: { motivo: 'usuario_inexistente' },
      ...contexto,
    })

    throw errorDeCredenciales()
  }

  // --- PASO 2: cuenta bloqueada -----------------------------------------
  //
  // Se responde con el mismo error generico que una contrasena incorrecta. Decir
  // "tu cuenta esta bloqueada" confirma que el email existe, y ademas el mismo
  // mensaje sirve de reloj: un atacante sabe que se acerco.
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

  // --- PASO 3: usuario sin contrasena (solo Google) ----------------------
  //
  // Sin este chequeo, `verificar` recibiria null. Y un null no falla: o lo
  // revienta, o peor, si el codigo lo trata como "no coincide" el usuario
  // recibe un error de contrasena incorrecta en vez de "inicia sesion con
  // Google", que lo manda a una pagina donde no puede hacer nada.
  if (usuario.passwordHash === null) {
    await deps.auditoria.registrar({
      tipo: 'login_fallido_sin_contrasena',
      userId: usuario.id,
      ...contexto,
    })

    throw errorDeCredenciales()
  }

  // --- PASO 4: verificar -------------------------------------------------
  const contrasenaCorrecta = await verificarContrasena(datos.contrasena, usuario.passwordHash)

  if (!contrasenaCorrecta) {
    const nuevoEstado = registrarIntentoFallido(usuario.estado, deps.politica, ahora)
    await deps.usuarios.actualizarBloqueo(usuario.id, nuevoEstado.estado)

    await deps.auditoria.registrar({
      tipo: 'login_fallido',
      userId: usuario.id,
      // Solo contadores. El mensaje al cliente sale de
      // mensajeDeCredencialesInvalidas, y dice "quedan N" SOLO si quedan pocos,
      // para no convertir el login en un oraculo sobre el estado de la cuenta.
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

  // --- Exito --------------------------------------------------------------
  //
  // Se limpia el estado de bloqueo SIEMPRE, no solo si habia fallos. Es una
  // escritura extra en el caso comun, y a cambio el contador nunca queda
  // desincronizado por ningun camino alternativo del codigo.
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

/**
 * Marca el email de un usuario como verificado.
 *
 * OJO CON QUE ESTO NO ES LO QUE HACE UN LINK DE VERIFICACION. Un link de
 * verificacion no lleva el userId en la URL: lleva un token de un solo uso, y
 * esta funcion es la que lo CONSUME. Por eso recibe el userId ya resuelto.
 *
 * Esa separacion es deliberada: si el endpoint recibiera el userId de la URL,
 * cualquiera podria verificar el email de otro con solo conocer su id.
 */
export async function verificarEmail(
  deps: DependenciasAuth,
  userId: string,
  instante: Date,
  contexto: { requestId?: string; ip?: string } = {},
): Promise<void> {
  const usuario = await deps.usuarios.buscarPorId(userId)

  if (!usuario) {
    // El token ya dio error antes de llegar aca, asi que un userId invalido
    // significa que el token apuntaba a un usuario borrado. Es un 500
    // disfrazado de 404.
    throw errorInterno('El token de verificacion apunta a un usuario inexistente')
  }

  // Verificar dos veces no es un error: el usuario puede hacer clic dos veces,
  // o abrir el link en dos pestanas. Se trata como exito.
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

/**
 * Estado de bloqueo de un usuario, para el endpoint de "mi cuenta".
 *
 * No devuelve los valores crudos, sino una vista ya interpretada. Es una
 * proteccion contra que un endpoint futuro exponga el `lockedUntil` en crudo y
 * otro lo interprete al reves, o que se mande al cliente un campo interno.
 */
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
