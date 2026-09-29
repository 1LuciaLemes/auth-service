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

import { config as cargarDotenv } from 'dotenv'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { EnvSchema, formatearErroresDeEntorno, type Env } from './env.schema.js'

/**
 * Donde vive el archivo .env.
 *
 * No se usa `'.env'` relativo al directorio de trabajo, porque en monorepo el
 * directorio de trabajo cambia segun desde donde se ejecute el comando: en
 * `npm run dev` desde apps/auth-service es ese mismo directorio, pero desde la
 * raiz del monorepo, o en vitest, es otro. Un path relativo ahi es una fuente
 * clasica de "en mi maquina funciona".
 *
 * Se resuelve desde la ubicacion de ESTE archivo. Al compilar, este modulo
 * queda en dist/config/env.js y el .env sigue en la raiz del proyecto, asi que
 * se sube un nivel. La funcion de abajo busca en ambos lugares y usa el
 * primero que exista.
 */
function ubicarArchivoDeEntorno(): string {
  const directorioDeEsteArchivo = dirname(fileURLToPath(import.meta.url))

  const candidatos = [
    // Fuente: src/config/env.ts -> ../../ = raiz del proyecto
    resolve(directorioDeEsteArchivo, '..', '..', '.env'),
    // Compilado: dist/config/env.js -> ../../../ = raiz del proyecto
    resolve(directorioDeEsteArchivo, '..', '..', '..', '.env'),
  ]

  for (const candidato of candidatos) {
    // existsSync devuelve false en vez de tirar si el path no existe, que es
    // justo el caso normal en produccion, donde no hay archivo .env.
    if (existsSync(candidato)) return candidato
  }

  // Ninguno existe, que es lo esperado en produccion: ahi las variables vienen
  // del entorno de Vercel. Se devuelve el primero como path por defecto, y
  // dotenv no encuentra nada y no hace nada. El `!` es seguro porque
  // `candidatos` es un array literal no vacio, y no hay forma de que el primer
  // elemento no exista; el compilador no lo sabe.
  return candidatos[0]!
}

/**
 * Carga el .env ANTES de validar.
 *
 * Esto faltaba, y era un bug que hacia que `npm run dev` no arrancara: el
 * schema se parseaba contra un process.env vacio, asi que la primera variable
 * obligatoria tiraba el proceso. Nada cargaba el archivo.
 *
 * El orden importa: cargar DESPUES de validar no serviria de nada.
 *
 * Nota sobre `override: false`: es el default y es lo correcto. Las variables
 * que ya estan en el entorno real (las de Vercel en produccion, o las que
 * pase la consola) tienen prioridad sobre el archivo. Si se pusiera en true, un
 * .env forgotten con llaves viejas sobreescribiria las llaves del deploy, que
 * es un descuido dificil de detectar porque todo pareceria funcionar con una
 * llave que no es la del entorno.
 */
cargarDotenv({ path: ubicarArchivoDeEntorno(), override: false })

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
      'Revisa el archivo .env. Los nombres de todas las variables',
      'estan documentados en .env.example.',
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
