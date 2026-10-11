interface CuerpoDeError {
  error?: string
  message?: string
}

export class ApiError extends Error {
  readonly code: string
  readonly status: number
  readonly retryAfter?: number

  constructor(
    code: string,
    message: string,
    status: number,
    opciones: { retryAfter?: number } = {},
  ) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.status = status
    this.retryAfter = opciones.retryAfter

    Object.setPrototypeOf(this, ApiError.prototype)
  }
}

export function crearErrorDesdeRespuesta(respuesta: Response): Promise<ApiError> {
  return respuesta
    .json()
    .then((cuerpo: CuerpoDeError) => {
      const retryAfter = Number(respuesta.headers.get('retry-after') ?? '') || undefined

      return new ApiError(
        cuerpo.error ?? 'server_error',
        cuerpo.message ?? `El servidor respondio con ${respuesta.status}`,
        respuesta.status,
        { retryAfter },
      )
    })
    .catch(() => new ApiError('server_error', `El servidor respondio con ${respuesta.status}`, respuesta.status))
}