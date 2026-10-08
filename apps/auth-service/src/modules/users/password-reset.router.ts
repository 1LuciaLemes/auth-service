import { Router } from 'express'
import { z } from 'zod'
import { envolverAsync } from '../../lib/async-handler.js'
import { conLimiteDeTasa } from '../../middleware/rate-limit.js'
import { contextoDeRequest } from '../../middleware/http-context.js'
import { validar } from '../../middleware/validate.js'
import type { RateLimiter } from '../../lib/rate-limit.js'
import {
  completarResetDeContrasena,
  MENSAJE_RESET_GENERICO,
  solicitarResetDeContrasena,
  type DependenciasReset,
} from './password-reset.service.js'

const schemaSolicitar = z.object({ email: z.string().trim().email() })

const schemaCompletar = z.object({
  token: z.string().min(1),
  nuevaContrasena: z.string().min(1).max(1024),
})

export interface DependenciasRouterReset {
  reset: DependenciasReset
  limitador?: RateLimiter
}

export function crearRouterDePasswordReset(deps: DependenciasRouterReset): Router {
  const router = Router()

  router.post(
    '/password-reset/request',
    ...(deps.limitador ? [conLimiteDeTasa(deps.limitador, 'auth:reset')] : []),
    validar(schemaSolicitar),
    envolverAsync(async (req, res) => {
      await solicitarResetDeContrasena(deps.reset, req.body, contextoDeRequest(req))
      res.status(200).json({ message: MENSAJE_RESET_GENERICO })
    }),
  )

  router.post(
    '/password-reset/confirm',
    validar(schemaCompletar),
    envolverAsync(async (req, res) => {
      await completarResetDeContrasena(deps.reset, req.body, contextoDeRequest(req))
      res.status(200).json({ ok: true })
    }),
  )

  return router
}