

import type { NextFunction, Request, Response } from 'express'
import { randomUUID } from 'node:crypto'
import { logger } from '../lib/logger.js'


export interface RequestConContexto extends Request {
  requestId: string

  logContext: Record<string, unknown>
}


export function contextoDeRequest(
  request: Request,
  res: Response,
  next: NextFunction,
): void {
  const req = request as RequestConContexto


  req.requestId = randomUUID()
  req.logContext = {}



  res.setHeader('X-Request-Id', req.requestId)

  const inicio = Date.now()

  res.on('finish', () => {
    const duracion = Date.now() - inicio
    const nivel = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info'




    logger[nivel](
      {
        requestId: req.requestId,
        method: req.method,

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
