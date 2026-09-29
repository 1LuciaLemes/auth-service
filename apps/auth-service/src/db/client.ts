/**
 * Cliente de la base de datos.
 *
 * Drizzle se conecta a Postgres con el driver `pg`. La conexion es un
 * "pool": un conjunto de conexiones abiertas que se reusan entre requests, en
 * lugar de abrir y cerrar una por cada peticion (que es lentisimo).
 *
 * Por que el pool importa en Vercel: cada funcion serverless es un proceso
 * separado. Si cada una abriera su propio pool, se multiplicarian las
 * conexiones y la base se caeria por exceeded. El limite max de 10 y el
 * timeout de 10 segundos evitan que eso pase.
 *
 * Ver explicacion.md, seccion 28.
 */

import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import * as schema from './schema.js'
import { env, isProduction } from '../config/env.js'

/**
 * El pool de conexiones.
 *
 * El limite max de conexiones lo decide la base, no la aplicacion. En Neon el
 * limite por defecto suele ser mayor, pero un pool chico del lado de la app es
 * lo que evita saturarla con conexiones que no se usan.
 */
const pool = new Pool({
  connectionString: env.DATABASE_URL,

  // Maximo de conexiones simultaneas del pool. Alto para desarrollo, bajo a
  // proposito para Vercel, donde muchas funciones pueden pedir conexion a la vez.
  max: isProduction ? 10 : 20,

  // Cuanto espera el pool por una conexion libre antes de tirar error.
  // Sin este limite, si la base esta saturada, los requests se quedan
  // colgados indefinidamente en vez de fallar rapido.
  connectionTimeoutMillis: 10_000,

  // Cuanto espera una consulta antes de abortarse. Sin esto, una consulta
  // bloqueada se queda colgada y arrastra la conexion con ella.
  idleTimeoutMillis: 30_000,
})

/**
 * Un fallo de conexion en cualquier momento, incluso en una consulta suelta,
 * emite un evento 'error' en el pool. Si no se escucha, Node tira un
 * unhandled error y **mata el proceso**, aunque la app siga funcionando bien.
 *
 * Esto es un detalle que sorprende: sin este handler, la aplicacion se cae
 * sola a las 3 de la mañana por un error de red en segundo plano.
 */
pool.on('error', (error) => {
  // A proposito se usa console.error y no el logger de pino: este archivo se
  // importa desde env.ts en casos de arranque temprano, y todavia no se puede
  // depender del logger. Es un punto de seguridad de la infraestructura.
  console.error('[db] error inesperado en el pool de conexiones:', error.message)
})

/**
 * La instancia de Drizzle, con el schema asociado.
 *
 * Pasar el schema permite usar el autocomplete y el type-checking de las
 * consultas: si escribo `db.select().from(usuario)`, TypeScript sabe que
 * columnas tiene `users`. Y si escribo mal un nombre de columna, da error de
 * compilacion y no un error de Postgres en produccion.
 */
export const db = drizzle(pool, { schema })

/** Exporta el pool para poder cerrarlo limpiamente en los tests. */
export { pool }
