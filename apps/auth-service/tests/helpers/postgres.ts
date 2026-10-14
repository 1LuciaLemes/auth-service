import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import * as schema from '../../src/db/schema.js'

export const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL

export const hayBaseDePrueba =
  typeof TEST_DATABASE_URL === 'string' && TEST_DATABASE_URL.length > 0

export function crearDbDePrueba() {
  if (!TEST_DATABASE_URL) {
    throw new Error('Falta TEST_DATABASE_URL para los tests de integracion')
  }

  const pool = new Pool({ connectionString: TEST_DATABASE_URL })
  return { db: drizzle(pool, { schema }), pool }
}
