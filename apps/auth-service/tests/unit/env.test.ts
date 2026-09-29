/**
 * Tests del validador de entorno.
 *
 * Aqui se importa env.schema.ts, NO env.ts, a proposito: el schema es codigo
 * puro y se puede testear sin tocar process.env. Si se importara env.ts, cada
 * test tendria que preparar todas las variables del sistema, y uno solo que
 * olvidara una fallaria por falta de configuracion y no por un bug real.
 *
 * Ver explicacion.md, seccion 31.
 */

import { describe, expect, it } from 'vitest'
import { EnvSchema } from '../../src/config/env.schema.js'

/** Configuracion minima valida. Cada test parte de aca y cambia lo que prueba. */
const base = {
  DATABASE_URL: 'postgresql://postgres:postgres@localhost:5432/auth_service',
  JWT_PRIVATE_KEY: 'PRIVADA',
  JWT_PUBLIC_KEY: 'PUBLICA',
  RESEND_API_KEY: 're_123',
  EMAIL_FROM: 'Auth <auth@ejemplo.com>',
  ALLOWED_ORIGINS: 'http://localhost:3000',
}

describe('EnvSchema', () => {
  it('acepta una configuracion minima valida', () => {
    const resultado = EnvSchema.safeParse(base)
    expect(resultado.success).toBe(true)
  })

  it('aplica los valores por defecto', () => {
    const resultado = EnvSchema.safeParse(base)
    expect(resultado.success).toBe(true)
    if (resultado.success) {
      expect(resultado.data.NODE_ENV).toBe('development')
      expect(resultado.data.PORT).toBe(3000)
      expect(resultado.data.ACCESS_TOKEN_TTL).toBe('15m')
      expect(resultado.data.REFRESH_TOKEN_TTL).toBe('30d')
      expect(resultado.data.PASSWORD_RESET_TTL).toBe('15m')
      expect(resultado.data.RATE_LIMIT_STORE).toBe('memory')
    }
  })

  it('rechaza faltar de una variable obligatoria', () => {
    for (const obligatoria of [
      'DATABASE_URL',
      'JWT_PRIVATE_KEY',
      'JWT_PUBLIC_KEY',
      'RESEND_API_KEY',
      'EMAIL_FROM',
      'ALLOWED_ORIGINS',
    ] as const) {
      const resultado = EnvSchema.safeParse({ ...base, [obligatoria]: undefined })
      expect(resultado.success, `${obligatoria} deberia ser obligatoria`).toBe(false)
    }
  })

  describe('ALLOWED_ORIGINS', () => {
    it('divide la lista por comas y quita espacios', () => {
      const resultado = EnvSchema.safeParse({
        ...base,
        ALLOWED_ORIGINS: ' http://a.com , http://b.com ',
      })
      expect(resultado.success).toBe(true)
      if (resultado.success) {
        expect(resultado.data.ALLOWED_ORIGINS).toEqual(['http://a.com', 'http://b.com'])
      }
    })

    it('rechaza una lista que queda vacia', () => {
      const resultado = EnvSchema.safeParse({ ...base, ALLOWED_ORIGINS: '  ,  ' })
      expect(resultado.success).toBe(false)
    })
  })

  describe('coercion de numeros', () => {
    it('convierte PORT de string a numero', () => {
      const resultado = EnvSchema.safeParse({ ...base, PORT: '8080' })
      expect(resultado.success).toBe(true)
      if (resultado.success) {
        expect(resultado.data.PORT).toBe(8080)
      }
    })

    it('rechaza un PORT que no es numero', () => {
      const resultado = EnvSchema.safeParse({ ...base, PORT: 'trescientos' })
      expect(resultado.success).toBe(false)
    })

    it('rechaza un limite de rate limit negativo', () => {
      const resultado = EnvSchema.safeParse({ ...base, RATE_LIMIT_REQUESTS_PER_MINUTE: '-1' })
      expect(resultado.success).toBe(false)
    })
  })

  describe('validacion cruzada de rate limit', () => {
    it('rechaza upstash sin credenciales', () => {
      // Este es el caso que justifica superRefine: sin esto, un deploy con
      // upstash y sin credenciales arrancaria bien y el rate limit estaria
      // desactivado hasta que alguien lo notara.
      const resultado = EnvSchema.safeParse({ ...base, RATE_LIMIT_STORE: 'upstash' })
      expect(resultado.success).toBe(false)
    })

    it('acepta upstash con credenciales completas', () => {
      const resultado = EnvSchema.safeParse({
        ...base,
        RATE_LIMIT_STORE: 'upstash',
        UPSTASH_REDIS_REST_URL: 'https://x.upstash.io',
        UPSTASH_REDIS_REST_TOKEN: 'token',
      })
      expect(resultado.success).toBe(true)
    })

    it('rechaza un valor de RATE_LIMIT_STORE desconocido', () => {
      const resultado = EnvSchema.safeParse({ ...base, RATE_LIMIT_STORE: 'redis' })
      expect(resultado.success).toBe(false)
    })
  })

  it('rechaza una APP_URL que no es URL', () => {
    const resultado = EnvSchema.safeParse({ ...base, APP_URL: 'no-es-una-url' })
    expect(resultado.success).toBe(false)
  })
})
