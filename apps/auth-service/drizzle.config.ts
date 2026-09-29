/**
 * Configuracion de drizzle-kit, la herramienta que genera y aplica las
 * migraciones.
 *
 * Que es una migracion y por que hace falta (explicacion.md, seccion 30):
 *
 * El schema del codigo y el de la base de datos se desincronizan. Cambiaste
 * una columna en el codigo y no corriste la migracion, o al reves. En local
 * puede funcionar y al desplegar se rompe.
 *
 * Una migracion es un archivo SQL versionado en Git que describe un cambio de
 * forma incremental y reproducible. Al estar en el repositorio, todos los
 * entornos (mi maquina, los tests, produccion) aplican los mismos cambios en
 * el mismo orden.
 *
 * El flujo de trabajo, y el paso que no hay que saltarse:
 *
 *   1. Cambiar el schema en src/db/schema.ts
 *   2. npm run db:generate   ->  genera el archivo .sql de la migracion
 *   3. LEER el .sql a mano
 *   4. npm run db:migrate    ->  lo aplica a la base local
 *   5. git add del .sql      ->  se versiona junto al codigo
 *   6. En produccion, correr db:migrate antes de desplegar
 *
 * El paso 3 es obligatorio. `generate` produce el SQL a partir del diff entre
 * el schema nuevo y el anterior, y generar es automatico, pero leerlo es
 * manual y es la ultima barrera contra un cambio que borre datos sin querer.
 */

import { defineConfig } from 'drizzle-kit'

export default defineConfig({
  schema: './src/db/schema.ts',

  // Donde se generan los archivos .sql de migracion.
  // OJO: esta carpeta se sube al repositorio a proposito. Las migraciones
  // tienen que estar versionadas, si no cada entorno aplicaria cambios
  // distintos. Lo que NO se versiona nunca es el contenido de la base.
  out: './src/db/migrations',

  dialect: 'postgresql',

  dbCredentials: {
    // La misma variable que usa la aplicacion. En local apunta al Postgres de
    // Docker, en produccion a Neon. Un solo lugar donde cambiar la conexion.
    url: process.env.DATABASE_URL ?? 'postgresql://postgres:postgres@localhost:5432/auth_service',
  },

  // Pide confirmacion antes de aplicar una migracion. Bueno para no romper la
  // base por accidente; en produccion se puede desactivar con --force.
  strict: true,

  verbose: true,
})
