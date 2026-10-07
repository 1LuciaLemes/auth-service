

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { generateKeyPairSync } from 'node:crypto'


async function cargarModuloJwt() {

  vi.resetModules()
  return import('../../src/lib/jwt.js')
}


const ESPERA_TOKEN_INVALIDO = { name: 'AppError', statusCode: 401, code: 'invalid_token' }


let privadaCorrecta: string
let publicaCorrecta: string

let publicaAtacante: string

beforeAll(() => {
  const bueno = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  })
  const malo = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  })

  privadaCorrecta = bueno.privateKey
  publicaCorrecta = bueno.publicKey
  publicaAtacante = malo.publicKey
})

const DATOS = {
  userId: 'usr_123',
  clientId: 'app_web',
  scopes: ['openid', 'email'],
  roles: ['user'],
  jti: 'jti_de_prueba',
}


const INSTANTE_FIJO = new Date('2030-06-15T12:00:00.000Z')


async function cargarJwtConLlavesDePrueba() {
  process.env.JWT_PRIVATE_KEY = privadaCorrecta
  process.env.JWT_PUBLIC_KEY = publicaCorrecta
  process.env.JWT_KEY_ID = 'key-test-01'
  process.env.APP_URL = 'https://auth.test'

  return cargarModuloJwt()
}

describe('JWT', () => {
  describe('duracionASegundos', () => {
    it('entiende segundos, minutos, horas y dias', async () => {
      const { duracionASegundos } = await cargarModuloJwt()

      expect(duracionASegundos('30s')).toBe(30)
      expect(duracionASegundos('15m')).toBe(900)
      expect(duracionASegundos('2h')).toBe(7200)
      expect(duracionASegundos('30d')).toBe(2_592_000)
    })

    it('rechaza una duracion mal formada, en vez de ignorarla', async () => {
      const { duracionASegundos } = await cargarModuloJwt()




      expect(() => duracionASegundos('15')).toThrow()
      expect(() => duracionASegundos('quince minutos')).toThrow()
      expect(() => duracionASegundos('15x')).toThrow()
      expect(() => duracionASegundos('-5m')).toThrow()
    })

    it('no acepta un numero decimal', async () => {
      const { duracionASegundos } = await cargarModuloJwt()



      expect(() => duracionASegundos('0.5m')).toThrow()
    })
  })

  describe('firma y verificacion', () => {

    beforeEach(() => {
      vi.useFakeTimers()
      vi.setSystemTime(INSTANTE_FIJO)
    })

    afterEach(() => {


      vi.useRealTimers()
    })

    it('firma un token y devuelve los claims correctos', async () => {
      const token = await firmarConLlavesDePrueba()

      const claims = await verificarToken(token, 'app_web')

      expect(claims.sub).toBe('usr_123')
      expect(claims.client_id).toBe('app_web')
      expect(claims.iss).toBe('https://auth.test')
      expect(claims.aud).toBe('app_web')
      expect(claims.scope).toBe('openid email')
      expect(claims.jti).toBe('jti_de_prueba')
    })

    it('el tiempo va en SEGUNDOS, no en milisegundos', async () => {
      const token = await firmarConLlavesDePrueba()
      const claims = await verificarToken(token, 'app_web')





      expect(claims.iat).toBe(1_907_755_200)

      expect(claims.exp).toBe(1_907_756_100)
    })

    it('el header lleva el kid y el algoritmo', async () => {
      const token = await firmarConLlavesDePrueba()




      const [headerB64] = token.split('.')
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'))



      expect(header.alg).toBe('ES256')
      expect(header.kid).toBe('key-test-01')
      expect(header.typ).toBe('JWT')
    })
  })

  describe('ataques', () => {
    it('rechaza un token firmado con otra llave', async () => {

      const token = await firmarConLlavesDePrueba()





      await expect(
        verificarToken(token, 'app_web', { publica: publicaAtacante }),
      ).rejects.toMatchObject(ESPERA_TOKEN_INVALIDO)
    })

    it('rechaza un token con el contenido modificado', async () => {
      const token = await firmarConLlavesDePrueba()
      const [header, , firma] = token.split('.')




      const payloadB64 = Buffer.from(
        JSON.stringify({ sub: 'usr_admin', iss: 'https://auth.test', aud: 'app_web' }),
      ).toString('base64url')

      const falsificado = `${header}.${payloadB64}.${firma}`

      await expect(verificarToken(falsificado, 'app_web')).rejects.toMatchObject(ESPERA_TOKEN_INVALIDO)
    })

    it('rechaza un token con alg: none', async () => {




      const payloadB64 = Buffer.from(
        JSON.stringify({
          sub: 'usr_admin',
          iss: 'https://auth.test',
          aud: 'app_web',
          exp: Math.floor(Date.now() / 1000) + 3600,
        }),
      ).toString('base64url')

      const headerB64 = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString(
        'base64url',
      )


      const tokenSinFirma = `${headerB64}.${payloadB64}.`





      await expect(verificarToken(tokenSinFirma, 'app_web')).rejects.toMatchObject(ESPERA_TOKEN_INVALIDO)
    })

    it('rechaza un token emitido por otro emisor', async () => {



      const token = await firmarConLlavesDePrueba()
      const [headerB64, payloadB64, firma] = token.split('.')

      const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'))
      payload.iss = 'https://otro-auth-server.example'
      const payloadModificado = Buffer.from(JSON.stringify(payload)).toString('base64url')

      await expect(
        verificarToken(`${headerB64}.${payloadModificado}.${firma}`, 'app_web'),
      ).rejects.toMatchObject(ESPERA_TOKEN_INVALIDO)
    })

    it('rechaza un token dirigido a otra app', async () => {
      const token = await firmarConLlavesDePrueba()






      await expect(verificarToken(token, 'app_otro')).rejects.toMatchObject(ESPERA_TOKEN_INVALIDO)
    })

    it('rechaza un token expirado', async () => {

      const haceUnaHora = new Date(Date.now() - 3_600_000)
      const token = await firmarConLlavesDePrueba({ ahora: haceUnaHora, ttl: '1s' })

      await expect(verificarToken(token, 'app_web')).rejects.toMatchObject(ESPERA_TOKEN_INVALIDO)
    })

    it('da el mismo mensaje para todos los fallos de verificacion', async () => {

      const expirado = await firmarConLlavesDePrueba({
        ahora: new Date(Date.now() - 3_600_000),
        ttl: '1s',
      })
      const basura = 'no-es-un-jwt'

      const mensajes: string[] = []
      for (const token of [expirado, basura]) {
        try {
          await verificarToken(token, 'app_web')
        } catch (e) {
          mensajes.push((e as Error).message)
        }
      }




      expect(mensajes).toHaveLength(2)
      expect(mensajes[0]).toBe(mensajes[1])
      expect(mensajes[0]).toBe('Token invalido')
    })

    it('rechaza un token con la firma cortada', async () => {
      const token = await firmarConLlavesDePrueba()
      const [header, payload, firma] = token.split('.')

      const firmaCorta = firma.slice(0, -4)

      await expect(
        verificarToken(`${header}.${payload}.${firmaCorta}`, 'app_web'),
      ).rejects.toMatchObject(ESPERA_TOKEN_INVALIDO)
    })
  })

  describe('la llave privada nunca sale del servidor', () => {
    it('un token no contiene la llave', async () => {
      const token = await firmarConLlavesDePrueba()





      expect(token).not.toContain('PRIVATE')
      expect(token).not.toContain(privadaCorrecta)
    })
  })

  describe('jwks', () => {
    it('publica la llave publica en formato JWKS', async () => {
      const modulo = await cargarJwtConLlavesDePrueba()
      const jwks = await modulo.obtenerJwks()

      expect(jwks.keys).toHaveLength(1)
      const [llave] = jwks.keys as Record<string, unknown>[]



      expect(llave.kty).toBe('EC')
      expect(llave.crv).toBe('P-256')


      expect(llave.kid).toBe('key-test-01')
      expect(llave.alg).toBe('ES256')
      expect(llave.use).toBe('sig')
    })

    it('nunca publica la llave privada', async () => {
      const modulo = await cargarJwtConLlavesDePrueba()
      const serializado = JSON.stringify(await modulo.obtenerJwks())





      expect(serializado).not.toContain('"d"')
      expect(serializado).not.toContain(privadaCorrecta)
      expect(serializado).not.toContain('PRIVATE')
    })
  })
})


async function firmarConLlavesDePrueba(datos: Partial<Parameters<
  Awaited<ReturnType<typeof cargarModuloJwt>>['firmarAccessToken']
>[0]> = {}) {
  const modulo = await cargarJwtConLlavesDePrueba()
  return modulo.firmarAccessToken({ ...DATOS, ...datos })
}


async function verificarToken(
  token: string,
  audiencia: string,
  alternativas: { publica?: string; appUrl?: string } = {},
) {




  process.env.JWT_PUBLIC_KEY = alternativas.publica ?? publicaCorrecta
  process.env.APP_URL = alternativas.appUrl ?? 'https://auth.test'

  const modulo = await cargarModuloJwt()
  return modulo.verificarAccessToken(token, { audienciaEsperada: audiencia })
}
