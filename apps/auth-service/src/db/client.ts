

import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import * as schema from './schema.js'
import { env, isProduction } from '../config/env.js'


const pool = new Pool({
  connectionString: env.DATABASE_URL,



  max: isProduction ? 10 : 20,




  connectionTimeoutMillis: 10_000,



  idleTimeoutMillis: 30_000,
})


pool.on('error', (error) => {



  console.error('[db] error inesperado en el pool de conexiones:', error.message)
})


export const db = drizzle(pool, { schema })


export { pool }
