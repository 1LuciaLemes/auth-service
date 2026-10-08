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
        '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4/0epaA05vOgQyt/\nN45SVThUbMBGxpl7oT9EvPrnv/mhRANCAARrfR4/IEX6msEi35XwYA/9odVm/Epc\nSWmdTjEeM/2og5tru6ozumOgy9esvaaqlzLxaJrevAd9VX6ULTRiUSGd\n-----END PRIVATE KEY-----',
      JWT_PUBLIC_KEY:
        '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEa30ePyBF+prBIt+V8GAP/aHVZvxK\nXElpnU4xHjP9qIOba7uqM7pjoMvXrL2mqpcy8Wia3rwHfVV+lC00YlEhnQ==\n-----END PUBLIC KEY-----',

      ALLOWED_ORIGINS: 'http://localhost:5173,https://app.example.com',

      RESEND_API_KEY: 're_test_dummy_key',
      EMAIL_FROM: 'test@example.com',
    },
  },
})
