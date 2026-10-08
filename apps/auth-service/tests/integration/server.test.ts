import { describe, expect, it } from 'vitest'
import request from 'supertest'
import {
  crearLimitadores,
  crearServidor,
  generarTokenDeVerificacionCon,
} from '../../src/server.js'
import { env } from '../../src/config/env.js'
import { MemoryRateLimiter } from '../../src/lib/rate-limit.js'
import type { DependenciasAuth } from '../../src/modules/auth/auth.service.js'
import type { DependenciasReset } from '../../src/modules/users/password-reset.service.js'
import {
  crearFakesDeMemoria,
  POLITICA_DEFAULT,
  type FakesDeMemoria,
} from '../helpers/fakes.js'

function depsDelServidor(fakes: FakesDeMemoria) {
  const auth: DependenciasAuth = {
    usuarios: fakes.usuarios,
    auditoria: fakes.auditoria,
    politica: POLITICA_DEFAULT,
    generarTokenDeVerificacion: generarTokenDeVerificacionCon(fakes.tokens),
    enviarEmailDeVerificacion: async ({ email, token }) => {
      fakes.emails.deVerificacion.push({ email, token })
    },
  }

  const reset: DependenciasReset = {
    usuarios: fakes.usuarios,
    tokens: fakes.tokens,
    auditoria: fakes.auditoria,
    appUrl: 'http://localhost:5173',
    enviarEmailDeReset: async ({ email, token, expiraEnMinutos }) => {
      fakes.emails.deReset.push({ email, token, expiraEnMinutos })
    },
  }

  return { auth, reset }
}

describe('servidor', () => {
  it('monta las rutas de auth bajo /api/v1', async () => {
    const fakes = crearFakesDeMemoria()
    const app = crearServidor(depsDelServidor(fakes))

    const respuesta = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'servidor@example.com', contrasena: 'UnaContrasenaLarga1!' })

    expect(respuesta.status).toBe(201)
  })

  it('expone el well-known jwks bajo /api/.well-known/jwks.json', async () => {
    const fakes = crearFakesDeMemoria()
    const app = crearServidor(depsDelServidor(fakes))

    const respuesta = await request(app).get('/api/.well-known/jwks.json')

    expect(respuesta.status).toBe(200)
    expect(respuesta.body.keys).toHaveLength(1)
    expect(respuesta.body.keys[0]).toMatchObject({
      kid: env.JWT_KEY_ID,
      alg: 'ES256',
      use: 'sig',
      kty: 'EC',
    })
  })

  it('mantiene el health check y el 404 de la capa base', async () => {
    const fakes = crearFakesDeMemoria()
    const app = crearServidor(depsDelServidor(fakes))

    const health = await request(app).get('/health')
    expect(health.status).toBe(200)

    const inexistente = await request(app).get('/api/v1/inexistente')
    expect(inexistente.status).toBe(404)
    expect(inexistente.body.error).toBe('not_found')
  })

  it('crea limitadores independientes con las reglas por defecto', () => {
    const limite = crearLimitadores()

    expect(limite.registro).not.toBe(limite.login)
    expect(limite.login).not.toBe(limite.reset)

    expect(limite.registro.consumir('clave').limite).toBe(10)
    expect(limite.login.consumir('clave').limite).toBe(20)
    expect(limite.reset.consumir('clave').limite).toBe(5)
  })

  it('permite inyectar un limitador propio y bloquea en tiempo real', async () => {
    const fakes = crearFakesDeMemoria()
    const app = crearServidor({
      ...depsDelServidor(fakes),
      limitadores: {
        registro: new MemoryRateLimiter({ maximo: 1, ventanaMs: 60_000 }),
      },
    })

    const primero = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'lento@example.com', contrasena: 'UnaContrasenaLarga1!' })
    expect(primero.status).toBe(201)

    const segundo = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'lento@example.com', contrasena: 'UnaContrasenaLarga1!' })
    expect(segundo.status).toBe(429)
  })
})