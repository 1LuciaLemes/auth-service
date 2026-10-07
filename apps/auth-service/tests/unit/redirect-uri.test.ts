

import { describe, expect, it } from 'vitest'
import {
  redirectUriPermitido,
  validarFormatoRedirectUri,
  validarListaDeRedirectUris,
} from '../../src/modules/clients/redirect-uri.js'

describe('validacion de redirect URIs', () => {
  describe('casos validos', () => {
    it('acepta una URL https normal', () => {
      const resultado = validarFormatoRedirectUri('https://app.example.com/callback')

      expect(resultado.valido).toBe(true)
    })

    it('acepta una URL con query string', () => {


      const resultado = validarFormatoRedirectUri('https://app.example.com/cb?tenant=acme')

      expect(resultado.valido).toBe(true)
    })

    it('acepta http en localhost, para desarrollo', () => {


      expect(validarFormatoRedirectUri('http://localhost:5173/callback').valido).toBe(true)
    })

    it('acepta http en 127.0.0.1', () => {
      expect(validarFormatoRedirectUri('http://127.0.0.1:3000/callback').valido).toBe(true)
    })

    it('acepta http en cualquier 127.x.x.x, que es el rango de loopback', () => {

      expect(validarFormatoRedirectUri('http://127.0.0.5:8080/callback').valido).toBe(true)
    })

    it('acepta http en [::1], que es loopback IPv6', () => {

      expect(validarFormatoRedirectUri('http://[::1]:3000/callback').valido).toBe(true)
    })

    it('acepta un puerto explicito en https', () => {
      expect(validarFormatoRedirectUri('https://app.example.com:8443/callback').valido).toBe(true)
    })
  })

  describe('protocolos rechazados', () => {
    it('rechaza javascript:', () => {


      const resultado = validarFormatoRedirectUri('javascript:alert(1)')

      expect(resultado.valido).toBe(false)
      if (!resultado.valido) expect(resultado.motivo).toBe('protocolo_no_permitido')
    })

    it('rechaza data:', () => {
      expect(validarFormatoRedirectUri('data:text/html,<script>alert(1)</script>').valido).toBe(false)
    })

    it('rechaza file:', () => {
      expect(validarFormatoRedirectUri('file:///etc/passwd').valido).toBe(false)
    })

    it('rechaza ftp:', () => {
      expect(validarFormatoRedirectUri('ftp://example.com/callback').valido).toBe(false)
    })

    it('rechaza http en un dominio que no es local', () => {


      const resultado = validarFormatoRedirectUri('http://app.example.com/callback')

      expect(resultado.valido).toBe(false)
      if (!resultado.valido) expect(resultado.motivo).toBe('protocolo_no_permitido')
    })

    it('rechaza http en un loopback DISFRAZADO', () => {


      const resultado = validarFormatoRedirectUri('http://localhost.evil.example/callback')

      expect(resultado.valido).toBe(false)
      if (!resultado.valido) expect(resultado.motivo).toBe('protocolo_no_permitido')
    })
  })

  describe('inyeccion', () => {
    it('rechaza un salto de linea, que es header injection', () => {



      const resultado = validarFormatoRedirectUri('https://app.com/cb\r\nSet-Cookie: a=b')

      expect(resultado.valido).toBe(false)
      if (!resultado.valido) expect(resultado.motivo).toBe('caracteres_invalidos')
    })

    it('rechaza un caracter nulo', () => {


      const resultado = validarFormatoRedirectUri('https://app.com/cb\u0000evil')

      expect(resultado.valido).toBe(false)
    })

    it('rechaza un espacio', () => {
      expect(validarFormatoRedirectUri('https://app.com/callback con espacio').valido).toBe(false)
    })
  })

  describe('forma de la URL', () => {
    it('rechaza una URL relativa', () => {



      const resultado = validarFormatoRedirectUri('/callback')

      expect(resultado.valido).toBe(false)
      if (!resultado.valido) expect(resultado.motivo).toBe('no_es_url')
    })

    it('rechaza un fragmento, porque nunca se envia al servidor', () => {


      const resultado = validarFormatoRedirectUri('https://app.com/cb#token=abc')

      expect(resultado.valido).toBe(false)
      if (!resultado.valido) expect(resultado.motivo).toBe('fragmento_no_permitido')
    })

    it('interpreta https:///callback como host "callback", no como URL sin host', () => {










      const resultado = validarFormatoRedirectUri('https:///callback')




      expect(resultado.valido).toBe(true)
    })

    it('rechaza https:// sin nada despues, que ni es URL', () => {
      const resultado = validarFormatoRedirectUri('https://')

      expect(resultado.valido).toBe(false)
      if (!resultado.valido) expect(resultado.motivo).toBe('no_es_url')
    })

    it('rechaza un string vacio', () => {
      const resultado = validarFormatoRedirectUri('')

      expect(resultado.valido).toBe(false)
      if (!resultado.valido) expect(resultado.motivo).toBe('vacia')
    })

    it('rechaza una URL demasiado larga', () => {


      const larga = `https://app.com/${'a'.repeat(2100)}`
      const resultado = validarFormatoRedirectUri(larga)

      expect(resultado.valido).toBe(false)
      if (!resultado.valido) expect(resultado.motivo).toBe('larga_demasiado')
    })
  })

  describe('coincidencia exacta en la comparacion', () => {
    const registradas = ['https://app.example.com/callback']

    it('acepta el URI exacto', () => {
      expect(redirectUriPermitido('https://app.example.com/callback', registradas)).toBe(true)
    })

    it('rechaza un path con un sufijo', () => {


      expect(redirectUriPermitido('https://app.example.com/callback/extra', registradas)).toBe(false)
    })

    it('rechaza un subdominio no registrado', () => {
      expect(redirectUriPermitido('https://evil.app.example.com/callback', registradas)).toBe(false)
    })

    it('rechaza un dominio que solo empieza igual', () => {
      expect(redirectUriPermitido('https://app.example.com.evil.com/callback', registradas)).toBe(
        false,
      )
    })

    it('rechaza una query distinta', () => {


      expect(redirectUriPermitido('https://app.example.com/callback?x=1', registradas)).toBe(false)
    })

    it('rechaza una diferencia de mayusculas en el host', () => {



      expect(redirectUriPermitido('https://APP.EXAMPLE.COM/callback', registradas)).toBe(false)
    })

    it('rechaza un puerto distinto', () => {
      expect(redirectUriPermitido('https://app.example.com:8443/callback', registradas)).toBe(false)
    })

    it('rechaza un esquema distinto', () => {
      expect(redirectUriPermitido('http://app.example.com/callback', registradas)).toBe(false)
    })

    it('rechaza una lista vacia de registradas', () => {


      expect(redirectUriPermitido('https://app.example.com/callback', [])).toBe(false)
    })

    it('funciona con varios URIs registrados', () => {
      const varias = [
        'https://app.example.com/callback',
        'https://app.example.com/staging/callback',
      ]

      expect(redirectUriPermitido('https://app.example.com/callback', varias)).toBe(true)
      expect(redirectUriPermitido('https://app.example.com/staging/callback', varias)).toBe(true)
      expect(redirectUriPermitido('https://app.example.com/prod/callback', varias)).toBe(false)
    })
  })

  describe('validacion de la lista completa', () => {
    it('acepta una lista valida', () => {
      const resultado = validarListaDeRedirectUris([
        'https://app.example.com/callback',
        'http://localhost:5173/callback',
      ])

      expect(resultado).toHaveLength(2)
    })

    it('rechaza una lista vacia', () => {

      expect(() => validarListaDeRedirectUris([])).toThrow()
    })

    it('rechaza mas de 10 URIs', () => {



      const muchos = Array.from({ length: 11 }, (_, i) => `https://app.com/cb${i}`)

      expect(() => validarListaDeRedirectUris(muchos)).toThrow()
    })

    it('rechaza duplicados', () => {
      expect(() =>
        validarListaDeRedirectUris([
          'https://app.com/cb',
          'https://app.com/cb',
        ]),
      ).toThrow()
    })

    it('reporta TODOS los URIs invalidos, no solo el primero', () => {


      let mensaje = ''
      try {
        validarListaDeRedirectUris([
          'https://ok.com/cb',
          'javascript:alert(1)',
          'no-es-una-url',
          'https://otro-ok.com/cb',
        ])
      } catch (error) {
        mensaje = JSON.stringify(error)
      }

      expect(mensaje).toContain('javascript')
      expect(mensaje).toContain('no-es-una-url')
    })

    it('falla si hay duplicados, en vez de deduplicar en silencio', () => {



      let mensaje = ''
      try {
        validarListaDeRedirectUris(['https://a.com/cb', 'https://b.com/cb', 'https://a.com/cb'])
      } catch (error) {
        mensaje = JSON.stringify(error)
      }

      expect(mensaje).toContain('duplicados')

      expect(mensaje).toContain('https://a.com/cb')
    })

    it('devuelve los URIs validos en el mismo orden en que se recibieron', () => {


      const resultado = validarListaDeRedirectUris([
        'https://z.com/cb',
        'https://a.com/cb',
        'https://m.com/cb',
      ])

      expect(resultado).toEqual(['https://z.com/cb', 'https://a.com/cb', 'https://m.com/cb'])
    })
  })
})
