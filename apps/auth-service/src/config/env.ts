

import { config as cargarDotenv } from 'dotenv'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { EnvSchema, formatearErroresDeEntorno, type Env } from './env.schema.js'


function ubicarArchivoDeEntorno(): string {
  const directorioDeEsteArchivo = dirname(fileURLToPath(import.meta.url))

  const candidatos = [

    resolve(directorioDeEsteArchivo, '..', '..', '.env'),

    resolve(directorioDeEsteArchivo, '..', '..', '..', '.env'),
  ]

  for (const candidato of candidatos) {


    if (existsSync(candidato)) return candidato
  }






  return candidatos[0]!
}


cargarDotenv({ path: ubicarArchivoDeEntorno(), override: false })


function cargarEntorno(): Env {
  const resultado = EnvSchema.safeParse(process.env)

  if (resultado.success) {
    return resultado.data
  }




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




  process.exit(1)
}

export const env: Env = cargarEntorno()


export const isProduction = env.NODE_ENV === 'production'
export const isTest = env.NODE_ENV === 'test'
export const isDevelopment = env.NODE_ENV === 'development'

export type { Env }
