import { beforeEach, describe, expect, it } from 'vitest'
import request from 'supertest'
import { Router } from 'express'
import { crearApp } from '../../src/app.js'
import { MemoryRateLimiter, type RateLimiter } from '../../src/lib/rate-limit.js'
import { generarTokenDeUnSoloUso } from '../../src/modules/users/one-time-token.js'
import {
  crearRouterDeAuth,
  type DependenciasRouterAuth,
  type LimitadoresDeAuth,
} from '../../src/modules/auth/auth.router.js'
import type { DependenciasAuth } from '../../src/modules/auth/auth.service.js'
import { crearFakesDeMemoria, POLITICA_DEFAULT, type FakesDeMemoria } from '../helpers/fakes.js'

const CONTRASENA = 'UnaContrasenaLarga1!'

function depsDeAuth(fakes: FakesDeMemoria): DependenciasRouterAuth {
  const auth: DependenciasAuth = {
    usuarios: fakes.usuarios,
    auditoria: fakes.auditoria,
    politica: POLITICA_DEFAULT,
    generarTokenDeVerificacion: async (userId) => {
      const emitido = generarTokenDeUnSoloUso('email_verification')
      await fakes.tokens.guardar({
        userId,
        purpose: emitido.purpose,
        tokenHash: emitido.tokenHash,
        expiresAt: emitido.expiresAt,
      })
      return { token: emitido.token, tokenHash: emitido.tokenHash, expira: emitido.expiresAt }
    },
    enviarEmailDeVerificacion: async ({ email, token }) => {
      fakes.emails.deVerificacion.push({ email, token })
    },
  }

  return {
    auth,
    verificacion: {
      usuarios: fakes.usuarios,
      tokens: fakes.tokens,
      auditoria: fakes.auditoria,
    },
  }
}

function appDeAuth(limitadores?: LimitadoresDeAuth) {
  const fakes = crearFakesDeMemoria()
  const api = Router()
  api.use('/v1/auth', crearRouterDeAuth({ ...depsDeAuth(fakes), limitadores }))
  return { app: crearApp(api), fakes }
}

describe('rutas de autenticacion', () => {
  let fakes: FakesDeMemoria

  beforeEach(() => {
    fakes = crearFakesDeMemoria()
  })

  describe('POST /api/v1/auth/register', () => {
    it('crea la cuenta, normaliza el email y devuelve 201', async () => {
      const { app } = appDeAuth()
      const respuesta = await request(app)
        .post('/api/v1/auth/register')
        .send({ email: '  Mayor@Example.COM ', contrasena: CONTRASENA, displayName: 'Mayor' })

      expect(respuesta.status).toBe(201)
      expect(respuesta.body.userId).toBeDefined()
      expect(respuesta.body.email).toBe('mayor@example.com')
    })

    it('rechaza un email ya registrado con 409', async () => {
      const { app } = appDeAuth()
      await request(app)
        .post('/api/v1/auth/register')
        .send({ email: 'doble@example.com', contrasena: CONTRASENA })
      const respuesta = await request(app)
        .post('/api/v1/auth/register')
        .send({ email: 'doble@example.com', contrasena: CONTRASENA })

      expect(respuesta.status).toBe(409)
      expect(respuesta.body.error).toBe('conflict')
    })

    it('rechaza una contrasena fuera de la politica con 400', async () => {
      const { app } = appDeAuth()
      const respuesta = await request(app)
        .post('/api/v1/auth/register')
        .send({ email: 'corta@example.com', contrasena: '123456' })

      expect(respuesta.status).toBe(400)
      expect(respuesta.body.error).toBe('validation_error')
    })

    it('rechaza un email sin formato valido con 400', async () => {
      const { app } = appDeAuth()
      const respuesta = await request(app)
        .post('/api/v1/auth/register')
        .send({ email: 'no-es-un-email', contrasena: CONTRASENA })

      expect(respuesta.status).toBe(400)
      expect(respuesta.body.error).toBe('validation_error')
    })

    it('rechaza un cuerpo que no es JSON valido con 400', async () => {
      const { app } = appDeAuth()
      const respuesta = await request(app)
        .post('/api/v1/auth/register')
        .set('Content-Type', 'application/json')
        .send('{no es json')

      expect(respuesta.status).toBe(400)
      expect(respuesta.body.error).toBe('invalid_request')
    })
  })

  describe('POST /api/v1/auth/login', () => {
    it('devuelve la cuenta con el estado de verificacion de email', async () => {
      const { app, fakes } = appDeAuth()
      await request(app).post('/api/v1/auth/register').send({ email: 'log@example.com', contrasena: CONTRASENA })

      const respuesta = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: 'log@example.com', contrasena: CONTRASENA })

      expect(respuesta.status).toBe(200)
      expect(respuesta.body.email).toBe('log@example.com')
      expect(respuesta.body.emailVerificado).toBe(false)
      void fakes
    })

    it('rechaza una contrasena incorrecta con 401', async () => {
      const { app } = appDeAuth()
      await request(app).post('/api/v1/auth/register').send({ email: 'clave@example.com', contrasena: CONTRASENA })

      const respuesta = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: 'clave@example.com', contrasena: 'OtraContrasenaIncorrecta2!' })

      expect(respuesta.status).toBe(401)
      expect(respuesta.body.error).toBe('invalid_credentials')
    })

    it('rechaza un email inexistente con 401 y el mismo mensaje generico', async () => {
      const { app } = appDeAuth()
      const respuesta = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: 'nadie@example.com', contrasena: CONTRASENA })

      expect(respuesta.status).toBe(401)
      expect(respuesta.body.error).toBe('invalid_credentials')
    })

    it('rechaza un cuerpo sin contrasena con 400', async () => {
      const { app } = appDeAuth()
      const respuesta = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: 'parcial@example.com' })

      expect(respuesta.status).toBe(400)
      expect(respuesta.body.error).toBe('validation_error')
    })
  })

  describe('POST /api/v1/auth/verify-email', () => {
    it('verifica el email con el token que recibio por email y lo marca en el login', async () => {
      const { app, fakes } = appDeAuth()
      await request(app)
        .post('/api/v1/auth/register')
        .send({ email: 'veri@example.com', contrasena: CONTRASENA })

      const email = fakes.emails.deVerificacion[0]
      expect(email.email).toBe('veri@example.com')

      const verificacion = await request(app)
        .post('/api/v1/auth/verify-email')
        .send({ token: email.token })

      expect(verificacion.status).toBe(200)
      expect(verificacion.body.ok).toBe(true)

      const login = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: 'veri@example.com', contrasena: CONTRASENA })
      expect(login.body.emailVerificado).toBe(true)
    })

    it('rechaza un token invalido con 401', async () => {
      const { app } = appDeAuth()
      const respuesta = await request(app)
        .post('/api/v1/auth/verify-email')
        .send({ token: 'token-inventado' })

      expect(respuesta.status).toBe(401)
      expect(respuesta.body.error).toBe('invalid_credentials')
    })

    it('no permite reusar el token de verificacion', async () => {
      const { app, fakes } = appDeAuth()
      await request(app)
        .post('/api/v1/auth/register')
        .send({ email: 'reuso@example.com', contrasena: CONTRASENA })

      const token = fakes.emails.deVerificacion[0].token
      await request(app).post('/api/v1/auth/verify-email').send({ token })
      const reuso = await request(app).post('/api/v1/auth/verify-email').send({ token })

      expect(reuso.status).toBe(401)
    })
  })

  describe('rate limit', () => {
    it('bloquea con 429 y Retry-After cuando se agota la ventana de login', async () => {
      const limitador: RateLimiter = new MemoryRateLimiter({ maximo: 3, ventanaMs: 60_000 })
      const { app } = appDeAuth({ login: limitador })

      for (let i = 0; i < 3; i += 1) {
        const respuesta = await request(app)
          .post('/api/v1/auth/login')
          .send({ email: 'bruteforce@example.com', contrasena: 'Incorrecta1!' })
        expect(respuesta.status).toBe(401)
      }

      const cuarto = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: 'bruteforce@example.com', contrasena: 'Incorrecta1!' })

      expect(cuarto.status).toBe(429)
      expect(cuarto.body.error).toBe('rate_limited')
      expect(Number(cuarto.headers['retry-after'])).toBeGreaterThan(0)
    })

    it('el limite de registro solo cuenta en /register, no en /login', async () => {
      const { app } = appDeAuth({ registro: new MemoryRateLimiter({ maximo: 2, ventanaMs: 60_000 }) })

      for (let i = 0; i < 2; i += 1) {
        await request(app)
          .post('/api/v1/auth/register')
          .send({ email: `r${i}@example.com`, contrasena: CONTRASENA })
      }

      const tercero = await request(app)
        .post('/api/v1/auth/register')
        .send({ email: 'r2@example.com', contrasena: CONTRASENA })
      expect(tercero.status).toBe(429)

      const login = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: 'r0@example.com', contrasena: CONTRASENA })
      expect(login.status).toBe(200)
    })
  })
})