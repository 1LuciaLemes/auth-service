


export type ErrorCode =

  | 'invalid_request'
  | 'validation_error'

  | 'invalid_credentials'
  | 'invalid_token'
  | 'invalid_grant'
  | 'invalid_client'

  | 'access_denied'
  | 'insufficient_scope'

  | 'not_found'
  | 'conflict'

  | 'rate_limited'

  | 'unsupported_grant_type'
  | 'unsupported_response_type'
  | 'server_error'


export class AppError extends Error {
  readonly code: ErrorCode
  readonly statusCode: number


  readonly metadata?: Record<string, unknown>


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



    Object.setPrototypeOf(this, AppError.prototype)
  }
}






export function errorDeValidacion(
  message: string,
  metadata?: Record<string, unknown>,
): AppError {
  return new AppError('validation_error', message, 400, { metadata })
}


export const MENSAJE_CREDENCIALES_INVALIDAS = 'Credenciales invalidas.'


export function errorDeCredenciales(
  mensaje: string = MENSAJE_CREDENCIALES_INVALIDAS,
): AppError {
  return new AppError('invalid_credentials', mensaje, 401)
}


export function errorDeToken(mensaje = 'Token invalido'): AppError {
  return new AppError('invalid_token', mensaje, 401)
}


export function errorDeGrant(mensaje = 'Grant no valido'): AppError {
  return new AppError('invalid_grant', mensaje, 400)
}


export function errorDeCliente(mensaje = 'Cliente no autenticado'): AppError {
  return new AppError('invalid_client', mensaje, 401)
}


export function errorDeAccesoDenegado(mensaje = 'Acceso denegado'): AppError {
  return new AppError('access_denied', mensaje, 403)
}


export function errorNoEncontrado(mensaje = 'No encontrado'): AppError {
  return new AppError('not_found', mensaje, 404)
}


export function errorDeConflicto(mensaje = 'El recurso ya existe'): AppError {
  return new AppError('conflict', mensaje, 409)
}


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


export function errorInterno(
  message = 'Error interno del servidor',
  metadata?: Record<string, unknown>,
): AppError {
  return new AppError('server_error', message, 500, {
    metadata,
    esErrorInterno: true,
  })
}


export function errorDesconocido(): AppError {
  return errorInterno()
}
