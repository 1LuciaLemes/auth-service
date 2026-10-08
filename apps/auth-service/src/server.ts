import { Router } from 'express'
import { crearApp } from './app.js'
import { MemoryRateLimiter, type RateLimiter } from './lib/rate-limit.js'
import type { RepositorioOneTimeTokens } from './modules/auth/ports.js'
import type { DependenciasAuth } from './modules/auth/auth.service.js'
import { crearRouterDeAuth, crearRouterDeJwks } from './modules/auth/auth.router.js'
import { generarTokenDeUnSoloUso } from './modules/users/one-time-token.js'
import type { DependenciasReset } from './modules/users/password-reset.service.js'
import { crearRouterDePasswordReset } from './modules/users/password-reset.router.js'

export interface LimitadoresDelServidor {
  registro: RateLimiter
  login: RateLimiter
  verificacion: RateLimiter
  reset: RateLimiter
}

export function crearLimitadores(): LimitadoresDelServidor {
  const cuartoDeHora = 15 * 60 * 1000

  return {
    registro: new MemoryRateLimiter({ maximo: 10, ventanaMs: cuartoDeHora }),
    login: new MemoryRateLimiter({ maximo: 20, ventanaMs: cuartoDeHora }),
    verificacion: new MemoryRateLimiter({ maximo: 20, ventanaMs: cuartoDeHora }),
    reset: new MemoryRateLimiter({ maximo: 5, ventanaMs: 60 * 60 * 1000 }),
  }
}

export interface DependenciasServidor {
  auth: DependenciasAuth
  reset: DependenciasReset
  limitadores?: Partial<LimitadoresDelServidor>
}

export function generarTokenDeVerificacionCon(tokens: RepositorioOneTimeTokens) {
  return async (userId: string) => {
    const emitido = generarTokenDeUnSoloUso('email_verification')

    await tokens.guardar({
      userId,
      purpose: emitido.purpose,
      tokenHash: emitido.tokenHash,
      expiresAt: emitido.expiresAt,
    })

    return { token: emitido.token, tokenHash: emitido.tokenHash, expira: emitido.expiresAt }
  }
}

export function crearServidor(deps: DependenciasServidor) {
  const api = Router()
  const limitadores = deps.limitadores ?? crearLimitadores()
  const tokens = deps.reset.tokens

  api.use(
    '/v1/auth',
    crearRouterDeAuth({
      auth: deps.auth,
      verificacion: {
        usuarios: deps.auth.usuarios,
        tokens,
        auditoria: deps.auth.auditoria,
      },
      limitadores,
    }),
  )

  api.use(
    '/v1/auth',
    crearRouterDePasswordReset({ reset: deps.reset, limitador: limitadores.reset }),
  )

  api.use(crearRouterDeJwks())

  return crearApp(api)
}