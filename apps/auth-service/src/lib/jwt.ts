

import { SignJWT, jwtVerify, importPKCS8, importSPKI, exportJWK, type JWTPayload } from 'jose'
import { env } from '../config/env.js'
import { errorDeToken } from './errors.js'


export interface ClaimsBase {

  sub: string

  iss: string

  aud: string

  client_id: string

  scope: string

  roles: string[]

  iat: number

  exp: number

  jti: string
}


function enSegundos(fecha: Date): number {
  return Math.floor(fecha.getTime() / 1000)
}


function emisor(): string {
  return env.APP_URL
}


export function duracionASegundos(duracion: string): number {
  const coincidencia = /^(\d+)([smhd])$/.exec(duracion.trim())

  if (!coincidencia) {
    throw new Error(
      `Duracion invalida: "${duracion}". Tiene que ser un numero seguido de s, m, h o d. Por ejemplo 15m.`,
    )
  }

  const cantidad = Number(coincidencia[1])
  const unidad = coincidencia[2]

  const multiplicador =
    unidad === 's' ? 1 : unidad === 'm' ? 60 : unidad === 'h' ? 3600 : 86_400

  return cantidad * multiplicador
}


export async function firmarAccessToken(datos: {
  userId: string
  clientId: string
  scopes: string[]
  roles: string[]
  jti: string

  ahora?: Date

  ttl?: string
}): Promise<string> {
  const ahora = datos.ahora ?? new Date()
  const ttl = duracionASegundos(datos.ttl ?? env.ACCESS_TOKEN_TTL)
  const llavePrivada = await importPKCS8(env.JWT_PRIVATE_KEY, 'ES256')

  return new SignJWT({
    client_id: datos.clientId,
    scope: datos.scopes.join(' '),
    roles: datos.roles,
  })
    .setProtectedHeader({
      alg: 'ES256',




      kid: env.JWT_KEY_ID,
      typ: 'JWT',
    })
    .setSubject(datos.userId)
    .setIssuer(emisor())



    .setAudience(datos.clientId)
    .setIssuedAt(enSegundos(ahora))
    .setExpirationTime(enSegundos(ahora) + ttl)
    .setJti(datos.jti)
    .sign(llavePrivada)
}


export async function verificarAccessToken(
  token: string,
  opciones: { audienciaEsperada?: string } = {},
): Promise<JWTPayload> {
  const llavePublica = await importSPKI(env.JWT_PUBLIC_KEY, 'ES256')

  try {
    const { payload } = await jwtVerify(token, llavePublica, {
      issuer: emisor(),




      ...(opciones.audienciaEsperada ? { audience: opciones.audienciaEsperada } : {}),




      algorithms: ['ES256'],
      clockTolerance: 5,
    })

    return payload
  } catch (error) {



    void error
    throw errorDeToken('Token invalido')
  }
}


export async function obtenerJwks(): Promise<{ keys: unknown[] }> {
  const publica = await importSPKI(env.JWT_PUBLIC_KEY, 'ES256')
  const jwk = await exportJWK(publica)

  return {
    keys: [
      {
        ...jwk,
        kid: env.JWT_KEY_ID,
        alg: 'ES256',
        use: 'sig',
      },
    ],
  }
}
