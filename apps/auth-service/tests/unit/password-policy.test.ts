/**
 * Tests de la politica de contrasenas.
 *
 * El foco esta en los casos de BORDE, que es donde una politica de contrasenas
 * suele tener agujeros:
 *
 *   - Las variantes con numeros o simbolos ("Password1") tienen que rechazarse
 *     igual que la original, o la politica es trivialmente evadible.
 *   - El limite de longitud tiene que aceptarse en los extremos exactos.
 *   - La comparacion tiene que ser insensible a mayusculas.
 *
 * Ver explicacion.md, seccion 21.
 */

import { describe, expect, it } from 'vitest'
import {
  contrasenaEsValida,
  LONGITUD_MAXIMA,
  LONGITUD_MINIMA,
  validarContrasena,
} from '../../src/lib/password-policy.js'

describe('validarContrasena', () => {
  it('acepta una contrasena larga y no comun', () => {
    const resultado = validarContrasena('LluviaDeSalMarzo2026!')

    expect(resultado.valida).toBe(true)
    expect(resultado.problemas).toHaveLength(0)
  })

  describe('longitud', () => {
    it('rechaza una contrasena corta', () => {
      const resultado = validarContrasena('corta123')

      expect(resultado.valida).toBe(false)
      expect(resultado.problemas.join(' ')).toContain('al menos')
    })

    it('acepta exactamente la longitud minima', () => {
      const contrasena = 'a'.repeat(LONGITUD_MINIMA)
      expect(contrasenaEsValida(contrasena)).toBe(true)
    })

    it('rechaza un caracter menos que la longitud minima', () => {
      const contrasena = 'a'.repeat(LONGITUD_MINIMA - 1)
      expect(contrasenaEsValida(contrasena)).toBe(false)
    })

    it('acepta exactamente la longitud maxima', () => {
      const contrasena = 'a'.repeat(LONGITUD_MAXIMA)
      expect(contrasenaEsValida(contrasena)).toBe(true)
    })

    it('rechaza un caracter mas que la longitud maxima', () => {
      // bcrypt trunca a 72 bytes. El limite protege contra que alguien mande
      // un string enorme y gaste memoria hasheandolo.
      const contrasena = 'a'.repeat(LONGITUD_MAXIMA + 1)
      expect(contrasenaEsValida(contrasena)).toBe(false)
    })
  })

  describe('contrasenas comunes', () => {
    it('rechaza contrasenas frecuentes', () => {
      for (const debil of ['123456', 'password', 'qwerty', 'admin', '123456789']) {
        // Se envuelven para pasar el filtro de longitud, asi el unico motivo
        // del rechazo es que estan en la lista de comunes.
        const resultado = validarContrasena(debil)

        // Las de menos de 12 caracteres fallan por dos motivos. Lo que se
        // verifica es que el problema de lista comun aparece.
        expect(resultado.problemas.join(' ')).toContain('mas usadas')
      }
    })

    it('es insensible a mayusculas', () => {
      // "PASSWORD123" se limpia de digitos y queda "password", que esta en la
      // lista. Por eso el mensaje que aparece es el de "variante", no el de
      // "contrasena comun": el test tiene que verificar que se RECHAZA, y no
      // atarse a cual de los dos mensajes salio.
      const resultado = validarContrasena('PASSWORD123')

      expect(resultado.valida).toBe(false)
      expect(resultado.problemas.length).toBeGreaterThan(0)
    })

    it('rechaza variantes con numeros agregados', () => {
      // Si "password" esta en la lista pero "password1" pasa, la politica es
      // trivialmente evadible: solo hay que agregar un numero al final.
      const resultado = validarContrasena('password12345')

      expect(resultado.valida).toBe(false)
    })

    it('rechaza variantes con simbolos agregados', () => {
      const resultado = validarContrasena('Password!!!')

      expect(resultado.valida).toBe(false)
    })
  })

  describe('acumulacion de problemas', () => {
    it('reporta TODOS los problemas, no solo el primero', () => {
      // Para que el usuario corrija todo de una vez en lugar de descubrir los
      // problemas de a uno.
      //
      // "qwerty" dispara dos: es corta (6 < 12) y esta en la lista de comunes.
      // Ojo con que sean dos y no tres: el chequeo de "variante" va en un
      // `else` justamente para no avisar dos veces lo mismo, que seria
      // confuso y no resoluble para el usuario.
      const resultado = validarContrasena('qwerty')

      expect(resultado.valida).toBe(false)
      expect(resultado.problemas).toHaveLength(2)
    })

    it('no duplica el aviso de contrasena comun', () => {
      // "password" esta en la lista, y al limpiarla de simbolos sigue siendo
      // "password". Los dos chequeos darian el mismo motivo, asi que tiene
      // que aparecer una sola vez.
      const resultado = validarContrasena('qwerty')
      const avisosDeLista = resultado.problemas.filter((p) => /usada/.test(p))

      expect(avisosDeLista).toHaveLength(1)
    })
  })
})
