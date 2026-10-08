import { describe, expect, it } from 'vitest'
import request from 'supertest'
import { Router } from 'express'
import { crearApp } from '../../src/app.js'
import { MemoryRateLimiter } from '../../src/lib/rate-limit.js'
import { verificarContrasena } from '../../src/lib/password.js'
import type { DependenciasReset } from '../../src/modules/users/password-reset.service.js'
import { MENSAJE_RESET_GENERICO } from '../../src/modules/users/password-reset.service.js'
import { crearRouterDePasswordReset } from '../../src/modules/users/password-reset.router.js'
import { crearFakesDeMemoria, type FakesDeMemoria } from '../helpers/fakes.js'

const CONTRASENA_NUEVA = 'NuevaContrasenaSegura2!'

function depsDeReset(fakes: FakesDeMemoria): DependenciasReset {
  return {
    usuarios: fakes.usuarios,
    tokens: fakes.tokens,
    auditoria: fakes.auditoria,
    appUrl: 'http://localhost:5173',
    enviarEmailDeReset: async ({ email, token, expiraEnMinutos }) => {
      fakes.emails.deReset.push({ email, token, expiraEnMinutos })
    },
  }
}

function appDeReset(limitador?: InstanceType<typeof MemoryRateLimiter>) {
  const fakes = crearFakesDeMemoria()
  const api = Router()
  api.use('/v1/auth', crearRouterDePasswordReset({ reset: depsDeReset(fakes), limitador }))
  return { app: crearApp(api), fakes }
}

describe('rutas de password reset', () => {
  it('responde 200 con un mensaje generico y envia el email al registrado', async () => {
    const { app, fakes } = appDeReset()
    await fakes.usuarios.crear({ email: 'pide@example.com', passwordHash: 'x' })

    const respuesta = await request(app)
      .post('/api/v1/auth/password-reset/request')
      .send({ email: 'pide@example.com' })

    expect(respuesta.status).toBe(200)
    expect(respuesta.body.message).toBe(MENSAJE_RESET_GENERICO)
    expect(fakes.emails.deReset).toHaveLength(1)
    expect(fakes.emails.deReset[0].email).toBe('pide@example.com')
    expect(fakes.emails.deReset[0].token).toBeDefined()
  })

  it('devuelve el MISMO mensaje para un email no registrado y no envia email', async () => {
    const { app, fakes } = appDeReset()

    const respuesta = await request(app)
      .post('/api/v1/auth/password-reset/request')
      .send({ email: 'nadie-reset@example.com' })

    expect(respuesta.status).toBe(200)
    expect(respuesta.body.message).toBe(MENSAJE_RESET_GENERICO)
    expect(fakes.emails.deReset).toHaveLength(0)
  })

  it('rechaza un email sin formato valido con 400', async () => {
    const { app } = appDeReset()

    const respuesta = await request(app)
      .post('/api/v1/auth/password-reset/request')
      .send({ email: 'no-valid' })

    expect(respuesta.status).toBe(400)
    expect(respuesta.body.error).toBe('validation_error')
  })

  it('completa el reset con el token del email y deja la nueva contrasena funcionando', async () => {
    const { app, fakes } = appDeReset()
    await fakes.usuarios.crear({ email: 'reset@example.com', passwordHash: 'hash-viejo' })
    await request(app)
      .post('/api/v1/auth/password-reset/request')
      .send({ email: 'reset@example.com' })

    const token = fakes.emails.deReset[0].token
    const respuesta = await request(app)
      .post('/api/v1/auth/password-reset/confirm')
      .send({ token, nuevaContrasena: CONTRASENA_NUEVA })

    expect(respuesta.status).toBe(200)
    expect(respuesta.body.ok).toBe(true)

    const usuario = fakes.usuariosInternos.get('reset@example.com')
    expect(usuario?.passwordHash).not.toBe('hash-viejo')
    expect(await verificarContrasena(usuario?.passwordHash ?? '', CONTRASENA_NUEVA)).toBe(true)
  })

  it('rechaza reusar el mismo token de reset', async () => {
    const { app, fakes } = appDeReset()
    await fakes.usuarios.crear({ email: 'reuso-reset@example.com', passwordHash: 'x' })
    await request(app)
      .post('/api/v1/auth/password-reset/request')
      .send({ email: 'reuso-reset@example.com' })

    const token = fakes.emails.deReset[0].token
    await request(app)
      .post('/api/v1/auth/password-reset/confirm')
      .send({ token, nuevaContrasena: CONTRASENA_NUEVA })

    const reuso = await request(app)
      .post('/api/v1/auth/password-reset/confirm')
      .send({ token, nuevaContrasena: CONTRASENA_NUEVA })

    expect(reuso.status).toBe(401)
    expect(reuso.body.error).toBe('invalid_credentials')
  })

  it('rechaza un token inventado con 401', async () => {
    const { app } = appDeReset()

    const respuesta = await request(app)
      .post('/api/v1/auth/password-reset/confirm')
      .send({ token: 'inventado', nuevaContrasena: CONTRASENA_NUEVA })

    expect(respuesta.status).toBe(401)
  })

  it('bloquea con 429 cuando la solicitud de reset supera el limite por hora', async () => {
    const { app } = appDeReset(new MemoryRateLimiter({ maximo: 2, ventanaMs: 3_600_000 }))

    await request(app)
      .post('/api/v1/auth/password-reset/request')
      .send({ email: 'spam@example.com' })
    await request(app)
      .post('/api/v1/auth/password-reset/request')
      .send({ email: 'spam@example.com' })

    const tercero = await request(app)
      .post('/api/v1/auth/password-reset/request')
      .send({ email: 'spam@example.com' })

    expect(tercero.status).toBe(429)
  })
})