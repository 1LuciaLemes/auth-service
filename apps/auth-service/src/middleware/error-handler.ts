/**
 * Middleware centralizado de errores.
 *
 * Un solo lugar que decide que hacer con cada error. Sin esto, cada endpoint
 * tendria que rememberar: si un error es 400 o 500, si el mensaje se muestra o
 * se oculta, si se registra en el audit log. Y es facil que uno se olvide,
 * sobre todo del audit log, que es el que hay que leer cuando algo sale mal.
 *
 * Ver explicacion.md, secciones 23 y 26.
 */

import type { NextFunction, Request, Response } from 'express'
import { ZodError } from 'zod'
import { AppError } from '../lib/errors.js'
import { logger } from '../lib/logger.js'
import type { RequestConContexto } from './request-context.js'

/**
 * Traduce un error a una respuesta HTTP.
 *
 * La regla que gobierna todo esto: **al cliente nunca se le da un detalle que
 * solo le sirva a un atacante.** Un error de base de datos puede traer nombres
 * de tabla, de columna o fragmentos de consulta, y un error de un modulo puede
 * confirmar que un email esta registrado. Todo eso va al log del servidor; la
 * respuesta es generica.
 */
export function manejarErrores(
  error: unknown,
  request: Request,
  res: Response,
  next: NextFunction,
): void {
  // El middleware de contexto ya paso por aca, asi que el requestId existe. Se
  // hace el cast porque el errorHandler se registra con `app.use` y Express pide
  // el `Request` mas general posible (mismo criterio que en request-context.ts).
  const req = request as RequestConContexto

  // Si la respuesta ya empezo a salir, no se puede cambiar el status. Se delega
  // el cierre a Express, que destruye la conexion.
  if (res.headersSent) {
    next(error)
    return
  }

  const requestId = req.requestId

  // --- 1. Errores de la aplicacion ---------------------------------
  if (error instanceof AppError) {
    if (error.statusCode >= 500) {
      // Error interno: se loguea COMPLETO, con el mensaje real.
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

    // Error interno: el mensaje real NUNCA se manda al cliente.
    if (error.esErrorInterno) {
      res.status(500).json({
        error: 'server_error',
        message: 'Error interno del servidor',
        requestId,
      })
      return
    }

    // El header Retry-After le dice al cliente cuando puede reintentar. Sin
    // el, un cliente bien hecho reintenta de inmediato y empeora el problema.
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

  // --- 2. Errores de Zod que sobrevivieron al middleware ------------
  // Pasa poco: `validar` ya los convierte a AppError. Queda por si alguien
  // valida fuera del middleware.
  if (error instanceof ZodError) {
    res.status(400).json({
      error: 'validation_error',
      message: 'Datos invalidos',
      requestId,
    })
    return
  }

  // --- 3. Error de body-parser --------------------------------------
  // Express tira un error con `type` cuando el JSON del body esta roto.
  // Si no se maneja, el cliente ve un 500 por un error que es suyo.
  if (error instanceof SyntaxError && 'body' in error) {
    res.status(400).json({
      error: 'invalid_request',
      message: 'El cuerpo de la peticion no es JSON valido',
      requestId,
    })
    return
  }

  // --- 4. Cualquier otra cosa --------------------------------------
  // Un error que no sabemos clasificar se registra entero y se responde
  // generico. Nunca se manda el mensaje: podria contener datos internos.
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
