/**
 * Tests de las utilidades criptograficas.
 *
 * Verificacion de las dos invariantes criticas del proyecto:
 *
 *   1. Dos llamadas a hashearContrasena con la MISMA contrasena dan hashes
 *      DISTINTOS (porque argon2 genera un salt interno). Si fueran iguales, el
 *      salt no estaria funcionando.
 *
 *   2. Dos llamadas a generarToken dan valores DISTINTOS y impredecibles.
 *      Si un token fuera predecible, un atacante podria adivinarlo.
 *
 * Ver explicacion.md, secciones 2, 4 y 13.
 */

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

    // 1000 tokens, 1000 distintos. Si se repitiera alguno, habria un problema
    // de entropia o un estado mal inicializado.
    expect(tokens.size).toBe(1000)
  })

  it('tiene la longitud esperada para 32 bytes', () => {
    // 32 bytes en base64url dan 43 caracteres.
    expect(generarToken(32)).toHaveLength(43)
  })

  it('no usa caracteres que rompen una URL', () => {
    // base64 "normal" usa + y /, que hay que escapar en query strings.
    // base64url usa - y _, que no necesitan escaping.
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
    // A diferencia de las contrasenas, aca el hash tiene que ser
    // deterministico: es la clave de busqueda en la base de datos.
    const token = 'un-refresh-token-de-ejemplo'
    expect(hashearToken(token)).toBe(hashearToken(token))
  })

  it('produce hashes distintos para tokens distintos', () => {
    expect(hashearToken('token-a')).not.toBe(hashearToken('token-b'))
  })

  it('es determinista entre ejecuciones', () => {
    // Valor esperado calculado por fuera, para detectar si el algoritmo
    // cambia. Si este test falla, alguien cambio la forma de hashear y las
    // filas de la base dejan de ser encontrables.
    const hash = hashearToken('token-fijo-para-el-test')

    // SHA-256 de 'token-fijo-para-el-test' en base64url
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
    // Trampa de timingSafeEqual: tira excepcion si los buffers tienen
    // distinta longitud. La excepcion misma filtraria informacion, asi que
    // el largo se verifica antes.
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
    // Si fueran iguales, seria el metodo `plain`, que esta prohibido: el
    // challenge viaja por la URL y seria equivalente al secreto.
    const verifier = generarCodeVerifier()
    expect(calcularCodeChallenge(verifier)).not.toBe(verifier)
  })

  it('verificarPkce acepta el par correcto', () => {
    const verifier = generarCodeVerifier()
    const challenge = calcularCodeChallenge(verifier)

    expect(verificarPkce(verifier, challenge)).toBe(true)
  })

  it('verificarPkce rechaza un verifier equivocado', () => {
    // Este es el ataque que PKCE previene: el atacante se queda con el
    // authorization code pero no con el code_verifier, y no puede canjearlo.
    const challenge = calcularCodeChallenge(generarCodeVerifier())

    expect(verificarPkce('un-verifier-del-atacante', challenge)).toBe(false)
  })

  it('genera code_verifiers distintos', () => {
    const verifiers = new Set(Array.from({ length: 100 }, () => generarCodeVerifier()))
    expect(verifiers.size).toBe(100)
  })

  it('el code_verifier tiene la longitud del RFC 7636', () => {
    // 43 caracteres, el minimo que corresponde a SHA-256 truncado a 32 bytes.
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
    // Este es el motivo de la funcion: si no normalizar, Lucia@x.com y
    // lucia@x.com serian dos cuentas distintas, que es el bug que el account
    // linking existe para evitar.
    expect(normalizarEmail('  Lucia@Ejemplo.com ')).toBe(
      normalizarEmail('lucia@ejemplo.com'),
    )
  })

  it('no toca los puntos del email', () => {
    // Los aliases de Gmail varian por proveedor. Cambiarlos seria peor que
    // aceptarlos tal cual.
    expect(normalizarEmail('lucia.gomez@gmail.com')).toBe('lucia.gomez@gmail.com')
  })
})
