

import type { NextFunction, Request, Response } from 'express'
import { ZodError } from 'zod'
import { AppError } from '../lib/errors.js'
import { logger } from '../lib/logger.js'
import type { RequestConContexto } from './request-context.js'


export function manejarErrores(
  error: unknown,
  request: Request,
  res: Response,
  next: NextFunction,
): void {



  const req = request as RequestConContexto



  if (res.headersSent) {
    next(error)
    return
  }

  const requestId = req.requestId


  if (error instanceof AppError) {
    if (error.statusCode >= 500) {

      logger.error(
        {
          requestId,
          code: error.code,
          mensaje: error.message,
          ...error.metadata,
        },
        'error interno',
      )
    } else if (error.statusCode === 429) {
      logger.warn({ requestId, code: error.code, ...error.metadata }, 'limite alcanzado')
    }


    if (error.esErrorInterno) {
      res.status(500).json({
        error: 'server_error',
        message: 'Error interno del servidor',
        requestId,
      })
      return
    }



    if (error.code === 'rate_limited') {
      const segundos = error.metadata?.segundosRetry
      if (typeof segundos === 'number') {
        res.setHeader('Retry-After', String(segundos))
      }
    }

    res.status(error.statusCode).json({
      error: error.code,
      message: error.message,
      requestId,
    })
    return
  }




  if (error instanceof ZodError) {
    res.status(400).json({
      error: 'validation_error',
      message: 'Datos invalidos',
      requestId,
    })
    return
  }




  if (error instanceof SyntaxError && 'body' in error) {
    res.status(400).json({
      error: 'invalid_request',
      message: 'El cuerpo de la peticion no es JSON valido',
      requestId,
    })
    return
  }




  logger.error(
    {
      requestId,
      mensaje: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    },
    'error no controlado',
  )

  res.status(500).json({
    error: 'server_error',
    message: 'Error interno del servidor',
    requestId,
  })
}
