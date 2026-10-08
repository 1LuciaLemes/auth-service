import type { Request } from 'express'
import type { RequestConContexto } from './request-context.js'

export function contextoDeRequest(
  request: Request,
): { requestId?: string; ip?: string } {
  const conContexto = request as RequestConContexto

  return {
    requestId: conContexto.requestId,
    ip: request.ip ?? undefined,
  }
}