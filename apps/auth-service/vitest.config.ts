import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // Los tests corren contra el codigo fuente en TypeScript, sin necesidad de
    // compilar antes. tsx se encarga de transpilar.
    include: ['tests/**/*.test.ts'],
    environment: 'node',

    // Los tests de integracion van a necesitar una base de datos Postgres.
    // Por defecto solo se corren los unitarios, que no tocan la base.
    // Para correr los de integracion:  npm test -- --include='tests/integration/**'
    exclude: ['tests/integration/**', 'node_modules/**', 'dist/**'],
  },
})
