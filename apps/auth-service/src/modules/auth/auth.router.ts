import { Router } from 'express'
import { z } from 'zod'
import { envolverAsync } from '../../lib/async-handler.js'
import { obtenerJwks } from '../../lib/jwt.js'
import type { RateLimiter } from '../../lib/rate-limit.js'
import { contextoDeRequest } from '../../middleware/http-context.js'
import { conLimiteDeTasa } from '../../middleware/rate-limit.js'
import { validar } from '../../middleware/validate.js'
import {
  iniciarSesion,
  registrarUsuario,
  type DependenciasAuth,
} from './auth.service.js'
import { canjearVerificacionDeEmail, type DependenciasVerificacionEmail } from './verify-email.js'

const CORREO = z.string().trim().email()
const CONTRASENA = z.string().min(1).max(1024)

const schemaRegistro = z.object({
  email: CORREO,
  contrasena: CONTRASENA,
  displayName: z.string().trim().min(1).max(100).optional(),
})

const schemaLogin = z.object({ email: CORREO, contrasena: CONTRASENA })
const schemaVerificacion = z.object({ token: z.string().min(1) })

export interface LimitadoresDeAuth {
  registro?: RateLimiter
  login?: RateLimiter
  verificacion?: RateLimiter
}

export interface DependenciasRouterAuth {
  auth: DependenciasAuth
  verificacion: DependenciasVerificacionEmail
  limitadores?: LimitadoresDeAuth
}

export function crearRouterDeAuth(deps: DependenciasRouterAuth): Router {
  const router = Router()
  const limiteRegistro = deps.limitadores?.registro
  const limiteLogin = deps.limitadores?.login
  const limiteVerificacion = deps.limitadores?.verificacion

  router.post(
    '/register',
    ...(limiteRegistro ? [conLimiteDeTasa(limiteRegistro, 'auth:register')] : []),
    validar(schemaRegistro),
    envolverAsync(async (req, res) => {
      const creado = await registrarUsuario(deps.auth, req.body, contextoDeRequest(req))
      res.status(201).json({ userId: creado.userId, email: creado.email })
    }),
  )

  router.post(
    '/verify-email',
    ...(limiteVerificacion ? [conLimiteDeTasa(limiteVerificacion, 'auth:verify-email')] : []),
    validar(schemaVerificacion),
    envolverAsync(async (req, res) => {
      await canjearVerificacionDeEmail(deps.verificacion, req.body.token, contextoDeRequest(req))
      res.status(200).json({ ok: true })
    }),
  )

  router.post(
    '/login',
    ...(limiteLogin ? [conLimiteDeTasa(limiteLogin, 'auth:login')] : []),
    validar(schemaLogin),
    envolverAsync(async (req, res) => {
      const sesion = await iniciarSesion(deps.auth, req.body, new Date(), contextoDeRequest(req))
      res.status(200).json({
        userId: sesion.userId,
        email: sesion.email,
        emailVerificado: sesion.emailVerificado,
      })
    }),
  )

  return router
}

export function crearRouterDeJwks(): Router {
  const router = Router()

  router.get(
    '/.well-known/jwks.json',
    envolverAsync(async (_req, res) => {
      res.status(200).json(await obtenerJwks())
    }),
  )

  return router
}