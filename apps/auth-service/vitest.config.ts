import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // Los tests corren contra el codigo fuente en TypeScript, sin necesidad de
    // compilar antes. Vitest se encarga de transpilar.
    include: ['tests/**/*.test.ts'],
    environment: 'node',

    // Los tests de integracion de BASE DE DATOS van a necesitar un Postgres.
    // Los de capa HTTP (supertest) no tocan la base, asi que corren siempre.
    //
    // Para correr solo los de base de datos, cuando haya un Postgres disponible:
    //   npm run test:db
    exclude: ['node_modules/**', 'dist/**'],

    /**
     * Variables de entorno de los tests.
     *
     * Esto es lo que hace que los tests NO dependan del `.env` de la maquina
     * de cada desarrollador, y hay una razon fuerte para que sea explicito.
     *
     * `src/config/env.ts` valida el entorno al importarse y llama a
     * `process.exit(1)` si falta algo. Los tests que importan el logger
     * importan el entorno, asi que sin este bloque, importar cualquier modulo
     * que toque el logger MATABA la corrida entera de tests. Y no con un error
     * claro: con un `process.exit` silencioso que hace que vitest reporte una
     * sola suite como fallida y no dice por que.
     *
     * El problema de fondo de un test que lee el `.env` real es otro: el
     * resultado del test depende de la maquina. Un test que pasa en la laptop
     * y falla en CI porque el `.env` de CI no tiene `ALLOWED_ORIGINS` es un
     * test que miente. Con los valores aca, el entorno de test es el mismo en
     * todas partes, siempre.
     *
     * Los valores son dummies y estan completos a proposito: el schema de Zod
     * valida formato y presencia, no que la API key de Resend sea real. Por eso
     * un dummy corta igual: el unico proposito de estos tests es ejercitar la
     * capa de codigo, no llamar servicios externos.
     */
    env: {
      NODE_ENV: 'test',
      LOG_LEVEL: 'silent',

      // Base de datos: los tests que de verdad la usan la saltan, pero el
      // modulo db/client.ts se importa en el grafo de varios archivos.
      DATABASE_URL: 'postgresql://test:test@localhost:5432/test_db',

      // JWT: el schema solo exige que existan. Las llaves se generan de verdad
      // en los tests de firma, no se usan estas.
      JWT_PRIVATE_KEY:
        '-----BEGIN EC PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END EC PRIVATE KEY-----',
      JWT_PUBLIC_KEY:
        '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----',

      ALLOWED_ORIGINS: 'http://localhost:5173,https://app.example.com',

      RESEND_API_KEY: 're_test_dummy_key',
      EMAIL_FROM: 'test@example.com',
    },
  },
})
