

import { describe, expect, it } from 'vitest'
import {
  calcularCodeChallenge,
  compararEnTiempoConstante,
  generarCodeVerifier,
  generarFamilyId,
  generarId,
  generarToken,
  hashearToken,
  normalizarEmail,
  verificarPkce,
} from '../../src/lib/crypto.js'

describe('generarToken', () => {
  it('produce tokens distintos cada vez', () => {
    const tokens = new Set(Array.from({ length: 1000 }, () => generarToken()))



    expect(tokens.size).toBe(1000)
  })

  it('tiene la longitud esperada para 32 bytes', () => {

    expect(generarToken(32)).toHaveLength(43)
  })

  it('no usa caracteres que rompen una URL', () => {


    const cienTokens = Array.from({ length: 100 }, () => generarToken()).join('')

    expect(cienTokens).not.toMatch(/[+/=]/)
  })

  it('permite cambiar el numero de bytes', () => {
    expect(generarToken(16)).toHaveLength(22)
    expect(generarToken(64)).toHaveLength(86)
  })
})

describe('generarId', () => {
  it('produce UUIDs distintos', () => {
    const ids = new Set(Array.from({ length: 1000 }, () => generarId()))
    expect(ids.size).toBe(1000)
  })

  it('tiene el formato de un UUID v4', () => {
    expect(generarId()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    )
  })
})

describe('hashearToken', () => {
  it('produce el mismo hash para el mismo token', () => {


    const token = 'un-refresh-token-de-ejemplo'
    expect(hashearToken(token)).toBe(hashearToken(token))
  })

  it('produce hashes distintos para tokens distintos', () => {
    expect(hashearToken('token-a')).not.toBe(hashearToken('token-b'))
  })

  it('es determinista entre ejecuciones', () => {



    const hash = hashearToken('token-fijo-para-el-test')


    expect(hash).toBe('HC36gOl748Sg_0WDTsvYuZSWN10HiA-AZBnb7MLXNrA')
  })

  it('un hash no revela el token original', () => {
    const token = 'un-token-secreto-de-32-bytes-minimo-aqui'
    expect(hashearToken(token)).not.toBe(token)
    expect(hashearToken(token)).not.toContain(token)
  })
})

describe('compararEnTiempoConstante', () => {
  it('devuelve true con strings iguales', () => {
    expect(compararEnTiempoConstante('secreto', 'secreto')).toBe(true)
  })

  it('devuelve false con strings distintos', () => {
    expect(compararEnTiempoConstante('secreto', 'secreto2')).toBe(false)
  })

  it('devuelve false y no lanza con longitudes distintas', () => {



    expect(compararEnTiempoConstante('corto', 'muchisimo mas largo')).toBe(false)
    expect(compararEnTiempoConstante('', 'a')).toBe(false)
  })

  it('maneja el string vacio', () => {
    expect(compararEnTiempoConstante('', '')).toBe(true)
  })
})

describe('PKCE', () => {
  it('el code_challenge es deterministico', () => {
    const verifier = 'un-code-verifier-de-prueba-1234567890abcd'

    expect(calcularCodeChallenge(verifier)).toBe(calcularCodeChallenge(verifier))
  })

  it('el code_challenge NO es el code_verifier', () => {


    const verifier = generarCodeVerifier()
    expect(calcularCodeChallenge(verifier)).not.toBe(verifier)
  })

  it('verificarPkce acepta el par correcto', () => {
    const verifier = generarCodeVerifier()
    const challenge = calcularCodeChallenge(verifier)

    expect(verificarPkce(verifier, challenge)).toBe(true)
  })

  it('verificarPkce rechaza un verifier equivocado', () => {


    const challenge = calcularCodeChallenge(generarCodeVerifier())

    expect(verificarPkce('un-verifier-del-atacante', challenge)).toBe(false)
  })

  it('genera code_verifiers distintos', () => {
    const verifiers = new Set(Array.from({ length: 100 }, () => generarCodeVerifier()))
    expect(verifiers.size).toBe(100)
  })

  it('el code_verifier tiene la longitud del RFC 7636', () => {

    const verifier = generarCodeVerifier()

    expect(verifier.length).toBeGreaterThanOrEqual(43)
    expect(verifier.length).toBeLessThanOrEqual(128)
  })
})

describe('normalizarEmail', () => {
  it('pasa a minusculas', () => {
    expect(normalizarEmail('Lucia@Ejemplo.COM')).toBe('lucia@ejemplo.com')
  })

  it('quita espacios al principio y al final', () => {
    expect(normalizarEmail('  lucia@ejemplo.com  ')).toBe('lucia@ejemplo.com')
  })

  it('hace que dos escrituras del mismo email coincidan', () => {



    expect(normalizarEmail('  Lucia@Ejemplo.com ')).toBe(
      normalizarEmail('lucia@ejemplo.com'),
    )
  })

  it('no toca los puntos del email', () => {


    expect(normalizarEmail('lucia.gomez@gmail.com')).toBe('lucia.gomez@gmail.com')
  })
})
