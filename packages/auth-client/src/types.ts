export interface DatoRegistro {
  email: string
  contrasena: string
  displayName?: string
}

export interface ResultadoRegistro {
  userId: string
  email: string
}

export interface DatoLogin {
  email: string
  contrasena: string
}

export interface ResultadoLogin {
  userId: string
  email: string
  emailVerificado: boolean
}

export interface DatoVerificacionEmail {
  token: string
}

export type ResultadoVerificacionEmail = {
  ok: true
}

export interface DatoSolicitudReset {
  email: string
}

export interface ResultadoSolicitudReset {
  message: string
}

export interface DatoCompletarReset {
  token: string
  nuevaContrasena: string
}

export type ResultadoCompletarReset = {
  ok: true
}

export interface ClaveJwks {
  kid: string
  alg: string
  use: string
  kty: string
  crv?: string
  x?: string
  y?: string
}

export interface Jwks {
  keys: ClaveJwks[]
}