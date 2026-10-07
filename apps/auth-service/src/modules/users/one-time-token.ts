

import { generarToken, hashearToken, compararEnTiempoConstante } from '../../lib/crypto.js'


export type PropositoToken = 'email_verification' | 'password_reset'


const TTL_POR_PROPOSITO: Record<PropositoToken, number> = {
  email_verification: 24 * 60 * 60,
  password_reset: 15 * 60,
}


export interface TokenAlmacenado {
  userId: string
  purpose: string
  tokenHash: string
  expiresAt: Date
  usedAt: Date | null
}


export interface TokenEmitido {

  token: string

  tokenHash: string
  expiresAt: Date
  purpose: PropositoToken
}


export function generarTokenDeUnSoloUso(proposito: PropositoToken, ahora = new Date()): TokenEmitido {












  const token = generarToken(32)

  return {
    token,
    tokenHash: hashearToken(token),
    expiresAt: new Date(ahora.getTime() + TTL_POR_PROPOSITO[proposito] * 1000),
    purpose: proposito,
  }
}


export { hashearToken, compararEnTiempoConstante }


export type MotivoTokenInvalido =
  | 'no_existe'
  | 'ya_usado'
  | 'expirado'
  | 'proposito_distinto'


export type ResultadoCanje =
  | { ok: true; userId: string }
  | { ok: false; motivo: MotivoTokenInvalido }


export function decidirCanje(
  row: TokenAlmacenado | null,
  purposeQueSePide: PropositoToken,
  ahora: Date = new Date(),
): ResultadoCanje {
  if (!row) return { ok: false, motivo: 'no_existe' }




  if (row.usedAt !== null) return { ok: false, motivo: 'ya_usado' }

  if (row.expiresAt.getTime() <= ahora.getTime()) return { ok: false, motivo: 'expirado' }




  if (row.purpose !== purposeQueSePide) return { ok: false, motivo: 'proposito_distinto' }

  return { ok: true, userId: row.userId }
}


export function ttlDeProposito(purpose: PropositoToken): number {
  return TTL_POR_PROPOSITO[purpose]
}
