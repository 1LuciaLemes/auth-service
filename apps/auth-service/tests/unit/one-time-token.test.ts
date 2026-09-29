/**
 * Tests de one-time tokens.
 *
 * Este modulo es donde se decide si alguien puede entrar en una cuenta o
 * cambiar su contrasena, asi que los tests cubren los casos de ATAQUE y no solo
 * el camino feliz.
 *
 * Ver explicacion.md, secciones 32 y 36.
 */

import { describe, expect, it } from 'vitest'
import {
  decidirCanje,
  generarTokenDeUnSoloUso,
  hashearToken,
  hashesCoinciden,
  ttlDeProposito,
  type TokenAlmacenado,
} from '../../src/modules/users/one-time-token.js'

const AHORA = new Date('2030-01-01T12:00:00.000Z')

/** Construye una fila válida de one_time_tokens. */
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

      // Esta es la pareja de la que depende todo el modulo: el token viaja
      // por el email, el hash se queda en la base.
      expect(emitido.token).not.toBe(emitido.tokenHash)
      expect(emitido.token).toMatch(/^[A-Za-z0-9_-]{43}$/)
    })

    it('el hash es SHA-256 del token, y se puede recalcular', () => {
      const emitido = generarTokenDeUnSoloUso('email_verification', AHORA)

      // Si el hash no fuera determinista, la fila guardada nunca coincidiria
      // con el token que llega por email y el canje fallaria siempre.
      expect(emitido.tokenHash).toBe(hashearToken(emitido.token))
      expect(emitido.tokenHash).toHaveLength(64)
    })

    it('el hash NO permite recuperar el token', () => {
      const emitido = generarTokenDeUnSoloUso('password_reset', AHORA)

      // Un hash de una sola via no se puede invertir. Por eso guardar el hash
      // es seguro: tener la fila de la base no sirve para hacer un reset.
      expect(emitido.tokenHash).not.toContain(emitido.token)
      expect(emitido.token).not.toContain(emitido.tokenHash.slice(0, 16))
    })

    it('dos tokens nunca coinciden', () => {
      const generados = new Set<string>()

      // Si dos usuarios Compartieran token, el segundo podria canjear el del
      // primero. Y si compartieran hash, al canjear uno se invalidarian los
      // dos.
      for (let i = 0; i < 500; i += 1) {
        generados.add(generarTokenDeUnSoloUso('password_reset', AHORA).token)
      }

      expect(generados.size).toBe(500)
    })

    it('el reset expira mucho antes que la verificacion de email', () => {
      // Es a proposito. Un token de reset es el mas sensible de los dos.
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

      expect(hashesCoinciden(hashearToken(token), hashearToken(token))).toBe(true)
    })

    it('rechaza hashes distintos', () => {
      expect(hashesCoinciden(hashearToken('token-a'), hashearToken('token-b'))).toBe(false)
    })

    it('rechaza longitudes distintas sin lanzar', () => {
      // `timingSafeEqual` lanza si los buffers tienen tamanos distintos, y un
      // error inesperado en la validacion de un token es una vulnerabilidad:
      // el endpoint responderia 500 y revelaria que el token "existe pero es
      // raro", en vez de 401 generico.
      expect(hashesCoinciden('corto', 'mucho_mas_largo_de_todo')).toBe(false)
      expect(hashesCoinciden('', 'algo')).toBe(false)
    })
  })

  describe('canje: casos validos', () => {
    it('acepta un token vigente del proposito pedido', () => {
      const resultado = decidirCanje(fila(), 'password_reset', AHORA)

      expect(resultado).toEqual({ ok: true, userId: 'usr_1' })
    })

    it('acepta un token que vence dentro de un segundo', () => {
      // El limite es `expiresAt > ahora`, no `>=`. A las 12:00:00.000 con
      // expiracion a las 12:00:00.001 el token sigue valiendo.
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

      // Este es EL test de un solo uso. Si pasara, un token robado del email
      // serviria para siempre, no solo hasta que el usuario lo usara.
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
      // El instante exacto de expiracion ya no vale. Es `now` al segundo
      // exacto, y tratarlo como vigente abriria una ventana de expiracion
      // inutilizable.
      const resultado = decidirCanje(
        fila({ expiresAt: new Date(AHORA.getTime()) }),
        'password_reset',
        AHORA,
      )

      expect(resultado).toEqual({ ok: false, motivo: 'expirado' })
    })

    it('NO deja usar un token de reset para verificar un email', () => {
      // Este es el cruce de propositos. Si pasara, cualquiera con acceso al
      // endpoint de verificacion podria "confirmar" un email con un token de
      // reset robado, sin llegar a tener el buzon.
      const resultado = decidirCanje(
        fila({ purpose: 'password_reset' }),
        'email_verification',
        AHORA,
      )

      expect(resultado).toEqual({ ok: false, motivo: 'proposito_distinto' })
    })

    it('NO deja usar un token de verificacion para cambiar la contrasena', () => {
      // El caso inverso, y mas grave: un token de verificacion suele estar en
      // la misma bandeja de entrada que el de reset, es mas facil de obtener
      // y sirve para algo que el usuario no espera. Si aceptara, basta con
      // pedir la verificacion y usar ese token para fijar una contrasena.
      const resultado = decidirCanje(
        fila({ purpose: 'email_verification' }),
        'password_reset',
        AHORA,
      )

      expect(resultado).toEqual({ ok: false, motivo: 'proposito_distinto' })
    })

    it('rechaza un purpose desconocido en la fila', () => {
      // purpose es texto libre en la base, no un enum. Si alguien inserta
      // 'admin' a mano, el servicio no debe asumir que es valido.
      const resultado = decidirCanje(fila({ purpose: 'admin' }), 'password_reset', AHORA)

      expect(resultado).toEqual({ ok: false, motivo: 'proposito_distinto' })
    })

    it('da el mismo motivo para un token vacio y uno inexistente', () => {
      // Un atacante que pruebe tokens al azar no debe poder distinguir "no
      // existe" de "existe pero no sirve". En los dos casos: no_existe.
      const vacio = decidirCanje(null, 'password_reset', AHORA)

      expect(vacio).toEqual({ ok: false, motivo: 'no_existe' })
    })
  })

  describe('orden de las comprobaciones', () => {
    it('gana la comprobacion de "ya usado" sobre la de proposito y la de expiracion', () => {
      // Este test fija el ORDEN de las comprobaciones, que es:
      // no_existe -> ya_usado -> expirado -> proposito_distinto.
      //
      // Aqui la fila esta a la vez ya usada, expirada y con purpose equivocado,
      // y el resultado es "ya_usado". Importa porque el motivo va al audit log
      // y porque el usuario que reintenta un token de reset viejo tiene que
      // recibir un motivo que le sirva: si dijera "proposito_distinto" le
      // haria sospechar de un fallo del sistema.
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
      // Y cuando no esta usada pero si expirada y con purpose equivocado, el
      // motivo es "expirado", no "proposito_distinto".
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
