

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


      const contrasena = 'a'.repeat(LONGITUD_MAXIMA + 1)
      expect(contrasenaEsValida(contrasena)).toBe(false)
    })
  })

  describe('contrasenas comunes', () => {
    it('rechaza contrasenas frecuentes', () => {
      for (const debil of ['123456', 'password', 'qwerty', 'admin', '123456789']) {


        const resultado = validarContrasena(debil)



        expect(resultado.problemas.join(' ')).toContain('mas usadas')
      }
    })

    it('es insensible a mayusculas', () => {




      const resultado = validarContrasena('PASSWORD123')

      expect(resultado.valida).toBe(false)
      expect(resultado.problemas.length).toBeGreaterThan(0)
    })

    it('rechaza variantes con numeros agregados', () => {


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







      const resultado = validarContrasena('qwerty')

      expect(resultado.valida).toBe(false)
      expect(resultado.problemas).toHaveLength(2)
    })

    it('no duplica el aviso de contrasena comun', () => {



      const resultado = validarContrasena('qwerty')
      const avisosDeLista = resultado.problemas.filter((p) => /usada/.test(p))

      expect(avisosDeLista).toHaveLength(1)
    })
  })
})
