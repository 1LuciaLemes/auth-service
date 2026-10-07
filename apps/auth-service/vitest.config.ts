import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {


    include: ['tests/**/*.test.ts'],
    environment: 'node',






    exclude: ['node_modules/**', 'dist/**'],


    env: {
      NODE_ENV: 'test',
      LOG_LEVEL: 'silent',



      DATABASE_URL: 'postgresql://test:test@localhost:5432/test_db',



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
