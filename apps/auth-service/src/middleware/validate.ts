/**
 * Middleware de validacion con Zod.
 *
 * Este es el que impide que un body malformado reviente el service. Sin el, un
 * `POST /auth/login` con body `"hola"` (en vez de un objeto) llega hasta
 * argon2 con `undefined` y produce un 500. En un auth service, eso es una
 * vulnerabilidad: cualquiera puede tumbar el servicio con un body vacio.
 *
 * Ver explicacion.md, secciones 27 y 29.
 */

import type { NextFunction, Request, Response } from 'express'
import { ZodError, type ZodType } from 'zod'
import { errorDeValidacion } from '../lib/errors.js'

/** De donde se leen los datos a validar. */
export type FuenteValidacion = 'body' | 'query' | 'params'

/**
 * Clave con la que se guardan los datos ya validados.
 *
 * Un simbolo en vez de un string tipo `datosValidadosQuery`, por dos razones:
 * un simbolo nunca colisiona con un campo real del request, y no ensucia el
 * objeto con propiedades que aparecen al hacer `console.log(req)`.
 */
const DATOS_VALIDADOS = Symbol('datosValidados')

/** Los tres conjuntos de datos validados de un request. */
export interface RequestConDatosValidados {
  body?: unknown
  query?: unknown
  params?: unknown
}

type RequestConDatos = Request & { [DATOS_VALIDADOS]?: RequestConDatosValidados }

/**
 * Lee los datos que dejo `validar` para una fuente dada.
 *
 * Se usa en los handlers para no perder el tipo: el `req.query` de Express es
 * `unknown` o un `ParsedQs` generico, mientras que lo que paso por Zod ya
 * tiene la forma exacta que declara el schema. Sin este helper, habria que
 * revalidar en cada handler y el tipado se perderia dos veces.
 *
 * Que tire si no se valido no es un problema: si un handler consulta datos que
 * no pasaron por `validar`, es un bug de programacion que tiene que loudly
 * fallar en desarrollo, no devolver `undefined` en produccion y romper mas
 * lejos.
 */
export function datosValidados<T>(req: Request, fuente: FuenteValidacion): T {
  const datos = (req as RequestConDatos)[DATOS_VALIDADOS]

  if (!datos || !(fuente in datos)) {
    throw new Error(
      `Se leyeron datos validados de '${fuente}' pero ese request no paso por validar('${fuente}')`,
    )
  }

  return datos[fuente] as T
}

/**
 * Valida una parte del request contra un schema de Zod.
 *
 * Recibe un `Request` y no un tipo mas especifico, por el mismo criterio de
 * variancia que en los otros middlewares: `app.use` acepta handlers que
 * laburan con el `Request` mas general.
 */
export function validar(schema: ZodType, fuente: FuenteValidacion = 'body') {
  return (request: Request, _res: Response, next: NextFunction): void => {
    const req = request as RequestConDatos

    try {
      const datos = schema.parse(req[fuente])

      // El body se reasigna a proposito, para que el handler vea el objeto ya
      // validado. En Express 4 `req.body` es writable; en Express 5 el modelo
      // cambia y esto habria que rethink, por eso el resto va en el simbolo.
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
