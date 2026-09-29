/**
 * Tests de firma y verificacion de JWT.
 *
 * Estos tests usan llaves ECDSA REALES generadas en memoria, no tokens de
 * ejemplo. Es deliberado: un token de ejemplo tiene una firma vieja y una
 * estructura que quizas no coincide con lo que produce la libreria hoy, asi
 * que el test pasaria probando el ejemplo y no el codigo.
 *
 * El bloque de ataques al final es la parte importante.
 *
 * Ver explicacion.md, secciones 5, 6 y 7.
 */

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { generateKeyPairSync } from 'node:crypto'

/**
 * Por que NO hay ningun import estatico de `jwt.js` en este archivo
 *
 * Este es el detalle que rompio la primera version de estos tests, y vale la
 * pena documentarlo porque el sintoma es desconcertante.
 *
 * `jwt.ts` importa `env.ts`, que valida el entorno AL IMPORTARSE y guarda el
 * resultado en una constante. Si este archivo tuviera `import { firmar } from
 * '.../jwt.js'` arriba, el modulo se cargaria antes de que el testieriera las
 * llaves de prueba, se quedaria con las llaves dummy del vitest.config, y
 * todos los tests fallarian con 'pkcs8 must be PKCS#8 formatted string'.
 *
 * Peor: cambiar `process.env.JWT_PUBLIC_KEY` DESPUES no sirve de nada, porque
 * `env` ya se parseo y el modulo tiene la llave vieja en su memoria. Un test
 * que "cambia la llave publica para comprobar que rechaza el token" estaria
 * pasando sin probar nada, porque en realidad se seguia verificando con la
 * misma llave de siempre.
 *
 * La solucion es `vi.resetModules()`, que vacia la cache de modulos. Despues,
 * el siguiente import crea una instancia NUEVA de jwt.ts y de env.ts, y ahi si
 * ve el entorno que hay en ese momento. Por eso todo pasa por
 * `cargarModuloJwt()`.
 */
async function cargarModuloJwt() {
  // Se invalida la cache para que env.ts se vuelva a leer.
  vi.resetModules()
  return import('../../src/lib/jwt.js')
}

/**
 * Como se comprueba que el error es un AppError SIN usar `instanceof`.
 *
 * Este es el segundo efecto secundario de `vi.resetModules()`, y no es
 * intuitivo. Al invalidar la cache, el proximo import de `jwt.ts` arrastra una
 * copia NUEVA de `errors.js`. El `AppError` que exporta esa copia es una clase
 * DISTINTA de la que importa este archivo, y `instanceof` compara identidades de
 * constructor. Por eso el test fallaba con 'expected error to be instance of
 * AppError' aunque el error fuera exactamente el correcto.
 *
 * Comprobar la FORMA (name, statusCode) en vez de la clase resuelve el problema
 * y ademas es un mejor test: lo que importa del punto de vista del endpoint no
 * es de que clase es el error, sino que responda 401 y con el codigo correcto.
 */
const ESPERA_TOKEN_INVALIDO = { name: 'AppError', statusCode: 401, code: 'invalid_token' }

/**
 * Pares de llaves reales, generados una vez para toda la suite.
 *
 * Se generan con la MISMA curva que el script de produccion (prime256v1 / ES256)
 * para que el test no valide un algoritmo que el service no usa.
 */
let privadaCorrecta: string
let publicaCorrecta: string
/** Llave de un atacante: sirve para firmar lo que quiera. */
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

/** Instante fijo para los tests que dependen de la hora. Explicado mas abajo. */
const INSTANTE_FIJO = new Date('2030-06-15T12:00:00.000Z')

/**
 * Las llaves del service vienen del entorno, que se valida al importar el
 * modulo. Para que estos tests usen las llaves de arriba, se sobreescriben las
 * variables de entorno ANTES de importar jwt.ts, con un import dinamico.
 *
 * Es un poco incomodo, y es el precio de que `env.ts` valide al importarse. La
 * alternativa (inyectar las llaves por parametro) seria mejor en teoria, pero
 * obligaria a pasar las llaves en cada llamada, y ese es justamente el error
 * que uno quiere commitir por descuido.
 */
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

      // Un TTL mal formado que pasa silenciosamente produce un token que
      // expira en mil millones de anios, y nadie descubre por que hasta que
      // alguien reutiliza un token robado un ano despues.
      expect(() => duracionASegundos('15')).toThrow()
      expect(() => duracionASegundos('quince minutos')).toThrow()
      expect(() => duracionASegundos('15x')).toThrow()
      expect(() => duracionASegundos('-5m')).toThrow()
    })

    it('no acepta un numero decimal', async () => {
      const { duracionASegundos } = await cargarModuloJwt()

      // 0.5m son 30 segundos, pero un TTL fraccionario es casi siempre un
      // error de calculo.
      expect(() => duracionASegundos('0.5m')).toThrow()
    })
  })

  describe('firma y verificacion', () => {
    /**
     * El reloj se congela para estos tests.
     *
     * Sin esto, un token firmado con una fecha fija en el pasado EXPIRA de
     * verdad mientras corre la suite, y el test falla con 'Token invalido' sin
     * que nada del codigo bajo prueba haya cambiado. Es un test que depende del
     * dia en que se ejecuta, que es la peor clase de test: pasa hoy, falla
     * manana, y nadie sabe por que.
     *
     * Congelar el reloj deja el resultado igual dentro de tres anos. Y al
     * verificar, `jose` tambien lee el reloj congelado, asi que los dos lados
     * ven la misma hora.
     */
    beforeEach(() => {
      vi.useFakeTimers()
      vi.setSystemTime(INSTANTE_FIJO)
    })

    afterEach(() => {
      // Sin restaurar, el reloj congelado se filtra a los otros archivos de
      // test que corran despues en el mismo worker.
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

      // 1907755200 es 2030-06-15T12:00:00Z en SEGUNDOS. Si el codigo usara
      // milisegundos, el valor seria 1907755200000, unas cuatro veces mayor de
      // lo que deberia, y `exp` caeria en el ano 63000: el token no expira
      // nunca y el bug es invisible hasta que hay un incidente.
      expect(claims.iat).toBe(1_907_755_200)
      // Con TTL de 15 minutos, exp son 900 segundos mas.
      expect(claims.exp).toBe(1_907_756_100)
    })

    it('el header lleva el kid y el algoritmo', async () => {
      const token = await firmarConLlavesDePrueba()
      // Un JWT son tres partes separadas por puntos: header, payload, firma.
      // El header va en la PRIMERA, no en la segunda. Con el indice equivocado
      // se estaba leyendo el payload y comparando `sub` contra 'ES256', que
      // por eso daba `undefined` en vez de un fallo de verificacion.
      const [headerB64] = token.split('.')
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'))

      // El kid es lo que permite rotar la llave sin downtime: el resource
      // server sabe que llave usar sin que se la tengan que decir.
      expect(header.alg).toBe('ES256')
      expect(header.kid).toBe('key-test-01')
      expect(header.typ).toBe('JWT')
    })
  })

  describe('ataques', () => {
    it('rechaza un token firmado con otra llave', async () => {
      // Firma con la llave buena...
      const token = await firmarConLlavesDePrueba()

      // ...y se verifica con la publica de un atacante. Si el service acepta
      // el token, cualquiera con un par de llaves propio puede emitir tokens
      // que el service tome por propios, y con eso se puede impersonar a
      // cualquier usuario.
      await expect(
        verificarToken(token, 'app_web', { publica: publicaAtacante }),
      ).rejects.toMatchObject(ESPERA_TOKEN_INVALIDO)
    })

    it('rechaza un token con el contenido modificado', async () => {
      const token = await firmarConLlavesDePrueba()
      const [header, , firma] = token.split('.')

      // Se cambia el subject por el de un admin. Es el ataque mas basico de
      // todos: un JWT es JSON legible, y si no se verifica la firma, editarlo
      // es question de editar texto.
      const payloadB64 = Buffer.from(
        JSON.stringify({ sub: 'usr_admin', iss: 'https://auth.test', aud: 'app_web' }),
      ).toString('base64url')

      const falsificado = `${header}.${payloadB64}.${firma}`

      await expect(verificarToken(falsificado, 'app_web')).rejects.toMatchObject(ESPERA_TOKEN_INVALIDO)
    })

    it('rechaza un token con alg: none', async () => {
      // El ataque mas viejo de JWT, y sigue funcionando en codigo que no fija
      // la lista de algoritmos aceptados. Consiste en firmar el token con
      // NINGUNA llave y declarar que el algoritmo es "none": la libreria, si
      // no sabe explicitamente que algoritmos permitir, lo acepta.
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

      // Firma vacia: es lo que "none" significa.
      const tokenSinFirma = `${headerB64}.${payloadB64}.`

      // Este test falla si en verificarAccessToken no esta
      // `algorithms: ['ES256']`. Ojo que jose TIENE esa proteccion por defecto
      // en versiones recientes, asi que este test es una garantia de que
      // nuestra llamada explicita sigue ahi si alguien la quita.
      await expect(verificarToken(tokenSinFirma, 'app_web')).rejects.toMatchObject(ESPERA_TOKEN_INVALIDO)
    })

    it('rechaza un token emitido por otro emisor', async () => {
      // El mismo user pero con issuer distinto. En un monorepo con varios auth
      // servers que comparten una llave, este token pasaria si no se validara
      // el issuer.
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

      // El token es legitimo y la firma es correcta, pero fue emitido para
      // 'app_web'. Un resource server de 'app_otro' NO debe aceptarlo: sin
      // validar `aud`, un token de la app A sirve para la app B, y un atacante
      // que tenga acceso legitimo a una sola app obtiene acceso a todas las
      // demas.
      await expect(verificarToken(token, 'app_otro')).rejects.toMatchObject(ESPERA_TOKEN_INVALIDO)
    })

    it('rechaza un token expirado', async () => {
      // Se firma con una fecha de hace una hora y TTL de 1 segundo.
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

      // Si se distinguiera "expirado" de "firma invalida", un atacante podria
      // usar tokens falsificados como oraculo: "el error es de expiracion, no
      // de firma", y sabria que el token era bien formado y solo viejo.
      expect(mensajes).toHaveLength(2)
      expect(mensajes[0]).toBe(mensajes[1])
      expect(mensajes[0]).toBe('Token invalido')
    })

    it('rechaza un token con la firma cortada', async () => {
      const token = await firmarConLlavesDePrueba()
      const [header, payload, firma] = token.split('.')
      // Se borran los ultimos caracteres de la firma.
      const firmaCorta = firma.slice(0, -4)

      await expect(
        verificarToken(`${header}.${payload}.${firmaCorta}`, 'app_web'),
      ).rejects.toMatchObject(ESPERA_TOKEN_INVALIDO)
    })
  })

  describe('la llave privada nunca sale del servidor', () => {
    it('un token no contiene la llave', async () => {
      const token = await firmarConLlavesDePrueba()

      // Es obvio, pero vale la pena dejarlo explicito: el token lleva la
      // llave PUBLICA (para que se pueda verificar) y NUNCA la privada. Si un
      // dia un token apareciera con material de la privada, podriamos firmar
      // lo que quisiéramos.
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

      // La curva P-256 de ES256. Si esto no cuadra, el resource server que
      // descargue el jwks no podra verificar nada.
      expect(llave.kty).toBe('EC')
      expect(llave.crv).toBe('P-256')
      // El kid tiene que coincidir con el del header de los tokens, o el
      // resource server no sabe que llave de la lista usar.
      expect(llave.kid).toBe('key-test-01')
      expect(llave.alg).toBe('ES256')
      expect(llave.use).toBe('sig')
    })

    it('nunca publica la llave privada', async () => {
      const modulo = await cargarJwtConLlavesDePrueba()
      const serializado = JSON.stringify(await modulo.obtenerJwks())

      // El parametro `d` de un JWK EC es la parte privada de la llave. Si
      // apareciera aqui, cualquiera que haga GET a /.well-known/jwks.json
      // podria firmar tokens falsos, y el endpoint de discovery publicandola
      // seria una catastrophe.
      expect(serializado).not.toContain('"d"')
      expect(serializado).not.toContain(privadaCorrecta)
      expect(serializado).not.toContain('PRIVATE')
    })
  })
})

/**
 * Firma un token con las llaves de prueba.
 *
 * Cada llamada recarga el modulo para que use las llaves de `beforeAll`. No es
 * eficiente, y da igual: son 20 milisegundos por test y la claridad vale mas.
 */
async function firmarConLlavesDePrueba(datos: Partial<Parameters<
  Awaited<ReturnType<typeof cargarModuloJwt>>['firmarAccessToken']
>[0]> = {}) {
  const modulo = await cargarJwtConLlavesDePrueba()
  return modulo.firmarAccessToken({ ...DATOS, ...datos })
}

/**
 * Verifica un token. Opcionalmente con otras llaves en el entorno, que es como
 * se prueba el rechazo por llave ajena.
 */
async function verificarToken(
  token: string,
  audiencia: string,
  alternativas: { publica?: string; appUrl?: string } = {},
) {
  // Primero se ponen las llaves buenas, y encima se pisan con las
  // alternativas. Al reves, un test que cambia solo la publica se quedaria sin
  // la privada y fallaria con un error que no tiene nada que ver con lo que
  // quiere probar.
  process.env.JWT_PUBLIC_KEY = alternativas.publica ?? publicaCorrecta
  process.env.APP_URL = alternativas.appUrl ?? 'https://auth.test'

  const modulo = await cargarModuloJwt()
  return modulo.verificarAccessToken(token, { audienciaEsperada: audiencia })
}
