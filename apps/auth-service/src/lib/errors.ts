/**
 * Errores de la aplicacion, tipados.
 *
 * Por que una clase de error propia en vez de `throw new Error('algo fallo')`:
 *
 * Un endpoint de auth necesita saber TRES cosas de cada error: que status HTTP
 * devolver, que cuerpo mandar, y si es un evento de seguridad que haya que
 * registrar en el audit log. Con errores de string, esas tres decisiones
 * quedan esparcidas por el codigo y es facil que un endpoint olvide una.
 *
 * Con esta clase, el error lleva la informacion consigo y el middleware
 * centralizado decide que hacer. Un error desconocido se traduce a 500 sin
 * detalles, para no filtrar informacion interna.
 *
 * Ver explicacion.md, secciones 23 y 26.
 */

/** Codigos de error de la API. El cliente los usa para decidir que mostrar. */
export type ErrorCode =
  // Entrada invalida
  | 'invalid_request'
  | 'validation_error'
  // Credenciales. OJO: estos tres son INTENCIONALMENTE el mismo mensaje.
  | 'invalid_credentials'
  | 'invalid_token'
  | 'invalid_grant'
  | 'invalid_client'
  // Permisos
  | 'access_denied'
  | 'insufficient_scope'
  // Recursos
  | 'not_found'
  | 'conflict'
  // Limites
  | 'rate_limited'
  // OAuth2 (nombres estandar de la spec)
  | 'unsupported_grant_type'
  | 'unsupported_response_type'
  | 'server_error'

/** Un error de la aplicacion, con la informacion de como responderlo. */
export class AppError extends Error {
  readonly code: ErrorCode
  readonly statusCode: number

  /**
   * Contexto adicional para el audit log. NUNCA debe contener un token ni
   * una contrasena: solo identificadores y motivos. Ver seccion 26.
   */
  readonly metadata?: Record<string, unknown>

  /**
   * Si es true, el errorHandler no muestra el mensaje al cliente y devuelve un
   * 500 generico. Se usa para fallos internos donde el detalle solo le
   * interesa a quien ataca.
   */
  readonly esErrorInterno: boolean

  constructor(
    code: ErrorCode,
    message: string,
    statusCode: number,
    opciones: { metadata?: Record<string, unknown>; esErrorInterno?: boolean } = {},
  ) {
    super(message)
    this.name = 'AppError'
    this.code = code
    this.statusCode = statusCode
    this.metadata = opciones.metadata
    this.esErrorInterno = opciones.esErrorInterno ?? false

    // Necesario para que `instanceof` funcione con el target de ES2022 en
    // cadenas de prototipos. Sin esto, el catch tipado no reconoce el error.
    Object.setPrototypeOf(this, AppError.prototype)
  }
}

// ============================================================
// FABRICAS
// ============================================================

/**
 * 400, entrada invalida.
 *
 * El mensaje SÍ se muestra al cliente: es informacion util sobre que esta mal
 * en su request, no una fuga.
 */
export function errorDeValidacion(
  message: string,
  metadata?: Record<string, unknown>,
): AppError {
  return new AppError('validation_error', message, 400, { metadata })
}

/**
 * 401, credenciales invalidas.
 *
 * OJO CON ESTE MENSAJE: es generico A PROPOSITO. El login devuelve
 * `invalid_credentials` tanto si el email no existe, como si la contrasena esta
 * mal, como si la cuenta esta bloqueada. Distinguirlos convertiria el endpoint
 * en un enumerador de cuentas registradas. Ver explicacion.md, seccion 23.
 */
export function errorDeCredenciales(
  mensaje = 'Credenciales invalidas',
): AppError {
  return new AppError('invalid_credentials', mensaje, 401)
}

/** 401, token ausente, vencido o invalido. */
export function errorDeToken(mensaje = 'Token invalido'): AppError {
  return new AppError('invalid_token', mensaje, 401)
}

/**
 * 400, el grant no es valido.
 *
 * Distinto de `invalid_token` a proposito: en el endpoint /token, un
 * `invalid_grant` significa que el authorization code o el refresh token no
 * servirian, mientras que un `invalid_token` seria un bearer token invalido.
 */
export function errorDeGrant(mensaje = 'Grant no valido'): AppError {
  return new AppError('invalid_grant', mensaje, 400)
}

/** 401, el cliente no se autentico o sus credenciales no coinciden. */
export function errorDeCliente(mensaje = 'Cliente no autenticado'): AppError {
  return new AppError('invalid_client', mensaje, 401)
}

/** 403, autenticado pero sin permiso. */
export function errorDeAccesoDenegado(mensaje = 'Acceso denegado'): AppError {
  return new AppError('access_denied', mensaje, 403)
}

/** 404, el recurso no existe. */
export function errorNoEncontrado(mensaje = 'No encontrado'): AppError {
  return new AppError('not_found', mensaje, 404)
}

/**
 * 409, conflicto.
 *
 * En este proyecto es para el registro con un email que ya existe. Ver la
 * nota de seguridad del endpoint de registro: se acepta por usabilidad, pero
 * conviene tenerlo presente.
 */
export function errorDeConflicto(mensaje = 'El recurso ya existe'): AppError {
  return new AppError('conflict', mensaje, 409)
}

/**
 * 429, se supero el limite de tasa.
 *
 * @param segundosRetry Cuanto falta para poder reintentar. Se manda en el
 * header `Retry-After`, que es lo que un cliente bien hecho lee.
 */
export function errorDeLimite(
  segundosRetry: number,
  metadata?: Record<string, unknown>,
): AppError {
  return new AppError(
    'rate_limited',
    'Demasiados intentos. Intenta de nuevo mas tarde.',
    429,
    { metadata: { ...metadata, segundosRetry } },
  )
}

/**
 * 500, error interno.
 *
 * El mensaje que se devuelve al cliente es SIEMPRE generico. El detalle real
 * va al log del servidor, nunca a la respuesta: un error de base de datos
 * puede contener nombres de tabla, de columna o fragmentos de consulta, que
 * le sirven a un atacante para entender el mapa del sistema.
 */
export function errorInterno(
  message = 'Error interno del servidor',
  metadata?: Record<string, unknown>,
): AppError {
  return new AppError('server_error', message, 500, {
    metadata,
    esErrorInterno: true,
  })
}

/** 500 sin mensaje util: un error que no sabemos clasificar. */
export function errorDesconocido(): AppError {
  return errorInterno()
}
