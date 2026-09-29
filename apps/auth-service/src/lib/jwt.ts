/**
 * Firma y verificacion de JWT con jose.
 *
 * Un JWT es un JSON, codificado en base64, con una firma al final. No esta
 * cifrado: cualquiera puede leer su contenido. La firma no esconde nada, lo que
 * hace es IMPEDIR QUE ALGUIEN LO CAMBIE.
 *
 * Que cambie un JWT no serviria de mucho por si solo, porque quien lo cambia no
 * tiene la llave privada. Pero lo que si sirve es esto: si el service acepta
 * como propio un token que el FIRMO otra persona, ese es el ataque. Con
 * verificacion de firma, un atacante no puede emitir tokens que el service
 * acepte como propios, porque no tiene la llave privada.
 *
 * Ver explicacion.md, secciones 5, 6 y 7.
 */

import { SignJWT, jwtVerify, importPKCS8, importSPKI, exportJWK, type JWTPayload } from 'jose'
import { env } from '../config/env.js'
import { errorDeToken } from './errors.js'

/** Lo que este service mete SIEMPRE en sus tokens. */
export interface ClaimsBase {
  /** Subject: el id del usuario. */
  sub: string
  /** Emisor. Debe ser identico al APP_URL del entorno donde se genero. */
  iss: string
  /** Audiencia: para quien es este token. */
  aud: string
  /** Id del cliente OAuth al que se le emitio. */
  client_id: string
  /** Scopes concedidos, separados por espacio. */
  scope: string
  /** Roles del usuario, para autorizar sin consultar la base. */
  roles: string[]
  /** Momento en que se emitio, en segundos desde epoch. */
  iat: number
  /** Expiracion, en segundos desde epoch. */
  exp: number
  /** Id unico del token, para poder revocar por referencia si hiciera falta. */
  jti: string
}

/**
 * Instantes en segundos desde epoch, que es como JWT representa el tiempo.
 *
 * No se usan milisegundos porque es una trampa clasica: un `iat` en
 * milisegundos es un numero enorme, y `exp` parece estar en el ano 57000. El
 * token no expira nunca y nadie sabe por que.
 */
function enSegundos(fecha: Date): number {
  return Math.floor(fecha.getTime() / 1000)
}

/** El emisor es exactamente el APP_URL, y no una variable aparte. */
function emisor(): string {
  return env.APP_URL
}

/**
 * Convierte una duracion tipo "15m" o "30d" en segundos.
 *
 * Se parsea la cadena a mano en vez de usar una libreria porque son cuatro
 * casos y meter una dependencia para esto no vale la pena. Lo que si importa es
 * que NO se acepte cualquier cosa: un TTL mal formado tiene que fallar al
 * arrancar, no producir un token que expire en 999999999999 segundos.
 */
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

/**
 * Genera un access token.
 *
 * @param jti Id unico del token. Lo genera el caller, no esta funcion, para que
 * quede en el log y se pueda correlacionar. Si esta funcion lo generara por
 * dentro, no habria forma de enlazar el token con el request que lo creo sin
 * volver a calcularlo.
 */
export async function firmarAccessToken(datos: {
  userId: string
  clientId: string
  scopes: string[]
  roles: string[]
  jti: string
  /** Se pasa para que el test no dependa del reloj. */
  ahora?: Date
  /** Override del TTL, para los tokens de vida corta. */
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
      // El keyId viaja en el header. Es lo que permite rotar la llave sin
      // downtime: se publica la nueva en el jwks.json, se cambia el JWT_KEY_ID,
      // y los tokens viejos siguen validandose con la llave vieja mientras
      // expiren. Ver explicacion.md, seccion 7.
      kid: env.JWT_KEY_ID,
      typ: 'JWT',
    })
    .setSubject(datos.userId)
    .setIssuer(emisor())
    // Se usa el clientId como audiencia. Es lo que impide que un token dado
    // para una app se pueda reutilizar contra otra: el resource server compara
    // `aud` con lo que espera.
    .setAudience(datos.clientId)
    .setIssuedAt(enSegundos(ahora))
    .setExpirationTime(enSegundos(ahora) + ttl)
    .setJti(datos.jti)
    .sign(llavePrivada)
}

/**
 * Verifica un access token y devuelve sus claims.
 *
 * TODAS las verificaciones importan, y por eso estan todas explicadas:
 *
 * 1. La FIRMA. Sin ella, cualquiera puede escribir el contenido de un token.
 * 2. El `exp`. Sin esta, un token robado sirve para siempre.
 * 3. El `iss`. Sin esta, un token emitido por OTRO service que use la misma
 *    llave seria aceptado. En un monorepo con varios auth servers, es un
 *    problema real.
 * 4. El `aud`. Sin esta, un token emitido para la app A sirve para la app B.
 *
 * @throws AppError 401 con mensaje generico si algo falla.
 */
export async function verificarAccessToken(
  token: string,
  opciones: { audienciaEsperada?: string } = {},
): Promise<JWTPayload> {
  const llavePublica = await importSPKI(env.JWT_PUBLIC_KEY, 'ES256')

  try {
    const { payload } = await jwtVerify(token, llavePublica, {
      issuer: emisor(),
      // Si no se pasa audiencia esperada, NO se valida. Es una decision
      // consciente: algunos resource servers solo necesitan saber quien es el
      // usuario, no para que app es. Para este service, que emite, la
      // audiencia siempre viene.
      ...(opciones.audienciaEsperada ? { audience: opciones.audienciaEsperada } : {}),
      // Se fija el algoritmo. Sin esto, un atacante podria mandar un token en
      // `alg: none`, que la libreria aceptaria si no lo sabe explicitamente.
      // Es el ataque mas viejo de JWT y sigue funcionando en codigo que no
      // fija la lista de algoritmos aceptados.
      algorithms: ['ES256'],
      clockTolerance: 5,
    })

    return payload
  } catch (error) {
    // Un solo mensaje para todos los fallos. Si se distinguiera "expirado" de
    // "firma invalida", un atacante podria usar tokens falsificados como
    // oraculo para intentar firmar uno de verdad.
    void error
    throw errorDeToken('Token invalido')
  }
}

/**
 * Publica la llave publica en formato JWKS.
 *
 * `jwks.json` es lo que permite que un resource server verifique nuestros
 * tokens sin tener la llave publica configurada a mano: la descarga sola, y
 * como el keyId viaja en el header del token, sabe que llave usar.
 *
 * Se expone solo la publica, y eso es lo correcto: no es un secreto, y
 * publicarla es justamente lo que hace que el esquema funcione.
 */
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
