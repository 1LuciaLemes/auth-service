/**
 * Middleware de contexto del request.
 *
 * Asigna a cada request un identificador unico y de ahi en adelante, todos los
 * logs de esa peticion lo incluyen. Asi se puede seguir una peticion completa
 * por los logs, aunque cruce varios modulos.
 *
 * Por que el ID se genera aca y no se acepta del cliente: si el cliente
 * pudiera elegirlo, un atacante podria mandar el mismo ID en todos sus
 * requests y mezclar los logs de sus intentos con los de otros. Es un
 * detalle chico, pero es exactamente el tipo de sutileza que hace que un log
 * deja de ser confiable.
 */

import type { NextFunction, Request, Response } from 'express'
import { randomUUID } from 'node:crypto'
import { logger } from '../lib/logger.js'

/** Campo del request donde queda el ID. */
export interface RequestConContexto extends Request {
  requestId: string
  /**
   * Datos de contexto que se agregan al logger para todos los logs del
   * request. Por ejemplo, tras autenticar, se agrega el userId.
   */
  logContext: Record<string, unknown>
}

/**
 * Se recibe un `Request` y no un `RequestConContexto` aunque el body del
 * middleware trabaje con el segundo.
 *
 * Es por variancia de tipos, y merece la pena entenderlo porque aparece en
 * cualquier middleware propio. `app.use` espera una funcion que acepte CUALQUIER
 * `Request`. Si el parametro esta declarado como `RequestConContexto`, que
 * tiene `requestId` obligatorio, el compilador exige que la funcion acepte
 * requests que podrian no tener ese campo: es mas especifico de lo que Express
 * garantiza, y por eso no es asignable.
 *
 * La regla general: un middleware toma el `Request` mas general posible y
 * AGREGA lo que necesita adentro, en vez de exigirlo de entrada.
 */
export function contextoDeRequest(
  request: Request,
  res: Response,
  next: NextFunction,
): void {
  const req = request as RequestConContexto

  // Se genera SIEMPRE en el servidor. Nunca se toma del header entrante.
  req.requestId = randomUUID()
  req.logContext = {}

  // Se devuelve en la respuesta, para que el cliente pueda reportar un
  // problema concreto sin tener que adivinar.
  res.setHeader('X-Request-Id', req.requestId)

  const inicio = Date.now()

  res.on('finish', () => {
    const duracion = Date.now() - inicio
    const nivel = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info'

    // Un solo lugar donde se registra el cierre de cada request. Se registra
    // en `finish`, que corre cuando la respuesta ya salio, para no sumar
    // latencia a la respuesta del usuario.
    logger[nivel](
      {
        requestId: req.requestId,
        method: req.method,
        // Sin query string: puede traer un authorization code o un token.
        path: req.originalUrl.split('?')[0],
        statusCode: res.statusCode,
        duracionMs: duracion,
        ...req.logContext,
      },
      'request completado',
    )
  })

  next()
}
