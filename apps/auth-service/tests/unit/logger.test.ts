

import { describe, expect, it } from 'vitest'
import pino from 'pino'
import {
  MARCA_REDACTADA,
  RUTAS_REDACTADAS,
  prefijoDeToken,
} from '../../src/lib/logger.js'


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



      const { log } = capturarSalida()
      const salida = log({ password: 'ContrasenaMuySecreta1!' })

      expect(salida).not.toContain('ContrasenaMuySecreta1!')
    })

    it('censura un authorization header anidado', () => {


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


      const { log } = capturarSalida()
      const salida = log({ userId: 'usr_123', email: 'a@b.com' })

      expect(salida).toContain('usr_123')
      expect(salida).toContain('a@b.com')
    })

    it('conserva la clave del campo, censurando solo el valor', () => {


      const { log } = capturarSalida()
      const salida = log({ refreshToken: 'secreto' })

      expect(salida).toContain('refreshToken')
      expect(salida).toContain(MARCA_REDACTADA)
    })

    it('censura un code de autorizacion, que viaja en la URL', () => {



      const { log } = capturarSalida()
      const salida = log({ code: 'ac_authorization_code_secreto' })

      expect(salida).not.toContain('ac_authorization_code_secreto')
    })

    it('censura la llave privada de firma del JWT', () => {


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




      expect(prefijo.length).toBeLessThanOrEqual(12)
    })

    it('no tira con un token corto', () => {
      expect(prefijoDeToken('abc')).toBe('abc...')
    })

    it('no tira con un token vacio', () => {


      expect(() => prefijoDeToken('')).not.toThrow()
    })
  })
})
