/**
 * El entorno de la aplicacion, ya validado.
 *
 * Este es el unico archivo que lee process.env. El resto del codigo importa
 * `env` de aca, y por lo tanto trabaja siempre con datos ya validados y
 * tipados. Ver explicacion.md, seccion 31.
 *
 * La separacion entre env.schema.ts y env.ts es deliberada:
 *
 *   - env.schema.ts  declara el schema con Zod. Es codigo PURO: no lee nada
 *                     del entorno, asi que se puede importar en los tests para
 *                     probar muchos casos sin que uno pise las variables del
 *                     otro.
 *
 *   - env.ts         hace el binding con process.env. Es el unico lugar del
 *                     proyecto donde process.env aparece.
 *
 * Si estuvieran juntos, importar el schema en un test ejecutaria el parseo
 * contra el entorno real de la maquina y fallaria.
 */

import { EnvSchema, formatearErroresDeEntorno, type Env } from './env.schema.js'

/**
 * Parsea y valida el entorno.
 *
 * Se hace de forma explicita, con try/catch, en vez de dejar que `parse`
 * lance. La diferencia es el mensaje: el error por defecto de Zod es un objeto
 * gigante, y cuando algo falta en el arranque de un deploy lo que se necesita
 * es leer "falta RESEND_API_KEY" en una linea.
 */
function cargarEntorno(): Env {
  const resultado = EnvSchema.safeParse(process.env)

  if (resultado.success) {
    return resultado.data
  }

  // No se usa console.log a proposito: todavia no hay logger, porque el logger
  // podria depender del entorno. Es el unico punto del arranque sin logger,
  // y por eso escribe directo a stderr.
  const mensaje = formatearErroresDeEntorno(resultado.error)

  process.stderr.write(
    [
      '',
      '======================================================',
      '  Faltan variables de entorno invalidas o requeridas.',
      '======================================================',
      mensaje,
      '',
      'Revisá el archivo .env. Los nombres de todas las variables',
      'están documentados en .env.example.',
      '',
      '======================================================',
      '',
    ].join('\n'),
  )

  // Sale con codigo 1 para que el orquestador (Docker, Vercel, CI) sepa
  // que el arranque fallo. Sin esto, un deploy con configuracion incompleta
  // podria quedar "sano" para el orquestador y romper mas tarde.
  process.exit(1)
}

export const env: Env = cargarEntorno()

/** Atajos para no repetir `env.NODE_ENV` en todo el codigo. */
export const isProduction = env.NODE_ENV === 'production'
export const isTest = env.NODE_ENV === 'test'
export const isDevelopment = env.NODE_ENV === 'development'

export type { Env }
