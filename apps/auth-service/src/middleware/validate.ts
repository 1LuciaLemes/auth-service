

import type { NextFunction, Request, Response } from 'express'
import { ZodError, type ZodType } from 'zod'
import { errorDeValidacion } from '../lib/errors.js'


export type FuenteValidacion = 'body' | 'query' | 'params'


const DATOS_VALIDADOS = Symbol('datosValidados')


export interface RequestConDatosValidados {
  body?: unknown
  query?: unknown
  params?: unknown
}

type RequestConDatos = Request & { [DATOS_VALIDADOS]?: RequestConDatosValidados }


export function datosValidados<T>(req: Request, fuente: FuenteValidacion): T {
  const datos = (req as RequestConDatos)[DATOS_VALIDADOS]

  if (!datos || !(fuente in datos)) {
    throw new Error(
      `Se leyeron datos validados de '${fuente}' pero ese request no paso por validar('${fuente}')`,
    )
  }

  return datos[fuente] as T
}


export function validar(schema: ZodType, fuente: FuenteValidacion = 'body') {
  return (request: Request, _res: Response, next: NextFunction): void => {
    const req = request as RequestConDatos

    try {
      const datos = schema.parse(req[fuente])




      if (fuente === 'body') {
        req.body = datos
      }

      const almacen = (req[DATOS_VALIDADOS] ??= {})
      almacen[fuente] = datos

      next()
    } catch (error) {
      if (error instanceof ZodError) {
        next(
          errorDeValidacion('Datos invalidos', {
            problemas: error.issues.map((issue) => ({
              campo: issue.path.join('.'),
              mensaje: issue.message,
            })),
          }),
        )
        return
      }
      next(error)
    }
  }
}
