

import { describe, expect, it } from 'vitest'
import {
  decidirCanje,
  generarTokenDeUnSoloUso,
  hashearToken,
  compararEnTiempoConstante,
  ttlDeProposito,
  type TokenAlmacenado,
} from '../../src/modules/users/one-time-token.js'

const AHORA = new Date('2030-01-01T12:00:00.000Z')


function fila(overrides: Partial<TokenAlmacenado> = {}): TokenAlmacenado {
  return {
    userId: 'usr_1',
    purpose: 'password_reset',
    tokenHash: 'hash_cualquiera',
    expiresAt: new Date(AHORA.getTime() + 60_000),
    usedAt: null,
    ...overrides,
  }
}

describe('one-time tokens', () => {
  describe('generacion', () => {
    it('devuelve el token en claro y su hash, y son distintos', () => {
      const emitido = generarTokenDeUnSoloUso('password_reset', AHORA)



      expect(emitido.token).not.toBe(emitido.tokenHash)
      expect(emitido.token).toMatch(/^[A-Za-z0-9_-]{43}$/)
    })

    it('el hash es SHA-256 del token, y se puede recalcular', () => {
      const emitido = generarTokenDeUnSoloUso('email_verification', AHORA)



      expect(emitido.tokenHash).toBe(hashearToken(emitido.token))








      expect(emitido.tokenHash).toHaveLength(43)
    })

    it('el hash NO permite recuperar el token', () => {
      const emitido = generarTokenDeUnSoloUso('password_reset', AHORA)



      expect(emitido.tokenHash).not.toContain(emitido.token)
      expect(emitido.token).not.toContain(emitido.tokenHash.slice(0, 16))
    })

    it('dos tokens nunca coinciden', () => {
      const generados = new Set<string>()




      for (let i = 0; i < 500; i += 1) {
        generados.add(generarTokenDeUnSoloUso('password_reset', AHORA).token)
      }

      expect(generados.size).toBe(500)
    })

    it('el reset expira mucho antes que la verificacion de email', () => {

      expect(ttlDeProposito('password_reset')).toBe(900)
      expect(ttlDeProposito('email_verification')).toBe(86_400)
    })

    it('la expiracion sale del TTL del proposito', () => {
      const reset = generarTokenDeUnSoloUso('password_reset', AHORA)
      const verificacion = generarTokenDeUnSoloUso('email_verification', AHORA)

      expect(reset.expiresAt.getTime() - AHORA.getTime()).toBe(900_000)
      expect(verificacion.expiresAt.getTime() - AHORA.getTime()).toBe(86_400_000)
    })
  })

  describe('comparacion de hashes', () => {
    it('acepta el mismo hash', () => {
      const token = generarTokenDeUnSoloUso('password_reset', AHORA).token

      expect(compararEnTiempoConstante(hashearToken(token), hashearToken(token))).toBe(true)
    })

    it('rechaza hashes distintos', () => {
      expect(compararEnTiempoConstante(hashearToken('token-a'), hashearToken('token-b'))).toBe(false)
    })

    it('rechaza longitudes distintas sin lanzar', () => {




      expect(compararEnTiempoConstante('corto', 'mucho_mas_largo_de_todo')).toBe(false)
      expect(compararEnTiempoConstante('', 'algo')).toBe(false)
    })
  })

  describe('canje: casos validos', () => {
    it('acepta un token vigente del proposito pedido', () => {
      const resultado = decidirCanje(fila(), 'password_reset', AHORA)

      expect(resultado).toEqual({ ok: true, userId: 'usr_1' })
    })

    it('acepta un token que vence dentro de un segundo', () => {


      const resultado = decidirCanje(
        fila({ expiresAt: new Date(AHORA.getTime() + 1) }),
        'password_reset',
        AHORA,
      )

      expect(resultado.ok).toBe(true)
    })

    it('acepta el token de verificacion en su propio endpoint', () => {
      const resultado = decidirCanje(
        fila({ purpose: 'email_verification' }),
        'email_verification',
        AHORA,
      )

      expect(resultado.ok).toBe(true)
    })
  })

  describe('canje: ataques y rechazos', () => {
    it('rechaza un token inexistente', () => {
      expect(decidirCanje(null, 'password_reset', AHORA)).toEqual({
        ok: false,
        motivo: 'no_existe',
      })
    })

    it('rechaza un token ya usado', () => {
      const resultado = decidirCanje(
        fila({ usedAt: new Date(AHORA.getTime() - 1000) }),
        'password_reset',
        AHORA,
      )



      expect(resultado).toEqual({ ok: false, motivo: 'ya_usado' })
    })

    it('rechaza un token expirado', () => {
      const resultado = decidirCanje(
        fila({ expiresAt: new Date(AHORA.getTime() - 1) }),
        'password_reset',
        AHORA,
      )

      expect(resultado).toEqual({ ok: false, motivo: 'expirado' })
    })

    it('rechaza un token que vence JUSTO ahora', () => {



      const resultado = decidirCanje(
        fila({ expiresAt: new Date(AHORA.getTime()) }),
        'password_reset',
        AHORA,
      )

      expect(resultado).toEqual({ ok: false, motivo: 'expirado' })
    })

    it('NO deja usar un token de reset para verificar un email', () => {



      const resultado = decidirCanje(
        fila({ purpose: 'password_reset' }),
        'email_verification',
        AHORA,
      )

      expect(resultado).toEqual({ ok: false, motivo: 'proposito_distinto' })
    })

    it('NO deja usar un token de verificacion para cambiar la contrasena', () => {




      const resultado = decidirCanje(
        fila({ purpose: 'email_verification' }),
        'password_reset',
        AHORA,
      )

      expect(resultado).toEqual({ ok: false, motivo: 'proposito_distinto' })
    })

    it('rechaza un purpose desconocido en la fila', () => {


      const resultado = decidirCanje(fila({ purpose: 'admin' }), 'password_reset', AHORA)

      expect(resultado).toEqual({ ok: false, motivo: 'proposito_distinto' })
    })

    it('da el mismo motivo para un token vacio y uno inexistente', () => {


      const vacio = decidirCanje(null, 'password_reset', AHORA)

      expect(vacio).toEqual({ ok: false, motivo: 'no_existe' })
    })
  })

  describe('orden de las comprobaciones', () => {
    it('gana la comprobacion de "ya usado" sobre la de proposito y la de expiracion', () => {








      const resultado = decidirCanje(
        fila({
          purpose: 'email_verification',
          usedAt: new Date(AHORA.getTime() - 1),
          expiresAt: new Date(AHORA.getTime() - 60_000),
        }),
        'password_reset',
        AHORA,
      )

      expect(resultado).toEqual({ ok: false, motivo: 'ya_usado' })
    })

    it('gana la expiracion sobre la de proposito', () => {


      const resultado = decidirCanje(
        fila({
          purpose: 'email_verification',
          expiresAt: new Date(AHORA.getTime() - 60_000),
        }),
        'password_reset',
        AHORA,
      )

      expect(resultado).toEqual({ ok: false, motivo: 'expirado' })
    })
  })
})
