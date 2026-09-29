/**
 * Tests del logger y del redact de secretos.
 *
 * Este archivo existe por una razon concreta: el valor de redactar tokens de
 * forma automatica NO se ve leyendo el codigo. Se ve cuando alguien escribe
 * `logger.info({ refreshToken }, ...)` por primera vez y descubre que el logger
 * ya lo censuro solo. Sin tests, esa proteccion se rompe en silencio la
 * primera vez que alguien cambia la forma de un log.
 *
 * Y hay un segundo motivo, mas grave: los logs suelen terminar en un servicio
 * de terceros con acceso de lectura para gente que no deberia ver tokens. Un
 * refresh token en un log no es una molestia, es una sesion robable.
 *
 * Ver explicacion.md, seccion 26.
 */

import { describe, expect, it } from 'vitest'
import pino from 'pino'
import {
  MARCA_REDACTADA,
  RUTAS_REDACTADAS,
  prefijoDeToken,
} from '../../src/lib/logger.js'

/**
 * Crea un logger con EXACTAMENTE la configuracion de redact de la app, pero
 * escribiendo en un array para poder inspeccionar la salida.
 *
 * Por que se reconstruye en vez de usar el logger real: pino escribe directo
 * al stream que se le dio al crearlo y no pasa por `console`, asi que no hay
 * forma de capturar la salida del logger de la app sin cambiar su
 * configuracion global (lo que contaminaria otros tests en paralelo).
 *
 * Reutilizar `RUTAS_REDACTADAS` y `MARCA_REDACTADA` es lo importante: el test
 * corre contra la lista real, asi que si alguien le saca un campo, falla.
 */
function capturarSalida(): { log: (objeto: Record<string, unknown>) => string } {
  const lineas: string[] = []

  const loggerDePrueba = pino(
    {
      level: 'info',
      redact: { paths: RUTAS_REDACTADAS, censor: MARCA_REDACTADA, remove: false },
    },
    {
      write: (linea: string) => {
        lineas.push(linea)
        return true
      },
    },
  )

  return {
    log: (objeto) => {
      loggerDePrueba.info(objeto, 'prueba')
      return lineas[lineas.length - 1] ?? ''
    },
  }
}

describe('logger y redact de secretos', () => {
  describe('redact de campos sensibles', () => {
    it('censura un refreshToken', () => {
      const { log } = capturarSalida()
      const salida = log({ refreshToken: 'rt_valor_secreto_123' })

      expect(salida).toContain(MARCA_REDACTADA)
      expect(salida).not.toContain('rt_valor_secreto_123')
    })

    it('censura una contrasena aunque nadie la loguee a proposito', () => {
      // Este es el caso de la red de seguridad: si manana alguien loguea el
      // body de un request de login para debuggear, la contrasena sale
      // censurada sin que ese alguien tenga que acordarse.
      const { log } = capturarSalida()
      const salida = log({ password: 'ContrasenaMuySecreta1!' })

      expect(salida).not.toContain('ContrasenaMuySecreta1!')
    })

    it('censura un authorization header anidado', () => {
      // Las rutas con punto de pino llegan a campos anidados. El header de
      // autorizacion trae el bearer token, asi que es el mas importante.
      const { log } = capturarSalida()
      const salida = log({ req: { headers: { authorization: 'Bearer eyJhbGciOi...' } } })

      expect(salida).not.toContain('Bearer eyJhbGciOi...')
    })

    it('censura cookies enteras', () => {
      const { log } = capturarSalida()
      const salida = log({ cookies: { session: 'valor-de-sesion-secreto' } })

      expect(salida).not.toContain('valor-de-sesion-secreto')
    })

    it('deja visibles los campos que NO son sensibles', () => {
      // Un redact que censurara todo no serviria para debuggear. Lo util es
      // poder seguir viendo el userId y el requestId.
      const { log } = capturarSalida()
      const salida = log({ userId: 'usr_123', email: 'a@b.com' })

      expect(salida).toContain('usr_123')
      expect(salida).toContain('a@b.com')
    })

    it('conserva la clave del campo, censurando solo el valor', () => {
      // Con remove: false, se ve QUE campo existia. Eso ayuda a entender un
      // bug ("el refreshToken vino vacio") sin exponer el contenido.
      const { log } = capturarSalida()
      const salida = log({ refreshToken: 'secreto' })

      expect(salida).toContain('refreshToken')
      expect(salida).toContain(MARCA_REDACTADA)
    })

    it('censura un code de autorizacion, que viaja en la URL', () => {
      // El authorization code es de un solo uso y dura 60 segundos, asi que es
      // el menos peligroso. Aun asi, si alguien loguea una URL de /authorize
      // para debuggear, el code va en el query string.
      const { log } = capturarSalida()
      const salida = log({ code: 'ac_authorization_code_secreto' })

      expect(salida).not.toContain('ac_authorization_code_secreto')
    })

    it('censura la llave privada de firma del JWT', () => {
      // El peor caso posible: con la llave privada, un atacante firma sus
      // propios access tokens y el service los acepta como propios.
      const { log } = capturarSalida()
      const salida = log({ privateKey: '-----BEGIN EC PRIVATE KEY-----abc123' })

      expect(salida).not.toContain('BEGIN EC PRIVATE KEY')
    })
  })

  describe('prefijoDeToken', () => {
    it('devuelve solo los primeros 8 caracteres', () => {
      expect(prefijoDeToken('abcdefghijklmnopqrstuvwxyz')).toBe('abcdefgh...')
    })

    it('NO incluye el resto del token', () => {
      const prefijo = prefijoDeToken('abcdefghijklmnopqrstuvwxyz')

      // La funcion existe para correlacionar logs sin filtrar el token. Si
      // aparecieran mas de 8 caracteres, un atacante con acceso al log tendria
      // justo la parte que importa de un refresh token.
      expect(prefijo.length).toBeLessThanOrEqual(12)
    })

    it('no tira con un token corto', () => {
      expect(prefijoDeToken('abc')).toBe('abc...')
    })

    it('no tira con un token vacio', () => {
      // Podria parecer que deberia tirar, pero no: es preferible un prefijo
      // vacio en el log a que el proceso muera por un token vacio.
      expect(() => prefijoDeToken('')).not.toThrow()
    })
  })
})
