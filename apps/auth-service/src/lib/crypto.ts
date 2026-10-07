

import {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto'






export function generarToken(bytes: number = 32): string {
  return randomBytes(bytes).toString('base64url')
}


export function generarId(): string {
  return randomUUID()
}


export function generarFamilyId(): string {
  return randomUUID()
}






export function hashearToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('base64url')
}






export function compararEnTiempoConstante(a: string, b: string): boolean {
  const bufferA = Buffer.from(a, 'utf8')
  const bufferB = Buffer.from(b, 'utf8')

  if (bufferA.length !== bufferB.length) {
    return false
  }

  return timingSafeEqual(bufferA, bufferB)
}






export function generarCodeVerifier(): string {
  return generarToken(32)
}


export function calcularCodeChallenge(codeVerifier: string): string {
  return createHash('sha256').update(codeVerifier, 'utf8').digest('base64url')
}


export function verificarPkce(codeVerifier: string, codeChallenge: string): boolean {
  return compararEnTiempoConstante(calcularCodeChallenge(codeVerifier), codeChallenge)
}






export function generarTokenDeUnSoloUso(): string {
  return generarToken(32)
}






export function normalizarEmail(email: string): string {
  return email.trim().toLowerCase()
}
