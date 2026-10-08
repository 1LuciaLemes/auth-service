import type { Request, RequestHandler } from 'express'
import { errorDeLimite } from '../lib/errors.js'
import type { RateLimiter } from '../lib/rate-limit.js'

export function conLimiteDeTasa(
  limitador: RateLimiter,
  prefijo: string,
  obtenerClave: (request: Request) => string = (request) =>
    request.ip ?? 'desconocida',
): RequestHandler {
  return (request, _response, next) => {
    const clave = `${prefijo}:${obtenerClave(request)}`
    const decision = limitador.consumir(clave)

    if (!decision.permitido) {
      next(errorDeLimite(decision.segundosParaReintentar, { clave, limite: decision.limite }))
      return
    }

    next()
  }
}