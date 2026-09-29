/**
 * Tests del hashing de contrasenas con Argon2id.
 *
 * Estos tests tardan mas que los otros del proyecto, y es lo esperado: cada
 * llamada a argon2id cuesta ~100 ms y 19 MB de memoria a proposito, porque esa
 * lentitud es el diseno de seguridad. Ver explicacion.md, seccion 3.
 */

import { beforeAll, describe, expect, it } from 'vitest'
import {
  hashearContrasena,
  inicializarHashDeReferencia,
  necesitaRehash,
  verificarContrasena,
  verificarContraReferencia,
} from '../../src/lib/password.js'

describe('hashearContrasena', () => {
  it('produce un hash que no es la contrasena', async () => {
    const contrasena = 'unaContrasenaLargaYSegura2026'
    const hash = await hashearContrasena(contrasena)

    expect(hash).not.toBe(contrasena)
  })

  it('el hash tiene el formato PHC de argon2id', async () => {
    const hash = await hashearContrasena('unaContrasenaLargaYSegura2026')

    // Formato: $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>
    // El salt esta embebido, por eso no hay una columna salt en la tabla.
    expect(hash).toMatch(/^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$/)
  })

  it('dos llamadas con la misma contrasena dan hashes DISTINTOS', async () => {
    const contrasena = 'unaContrasenaLargaYSegura2026'

    const primerHash = await hashearContrasena(contrasena)
    const segundoHash = await hashearContrasena(contrasena)

    // Esta es la prueba del salt: si fueran iguales, dos usuarios con la misma
    // contrasena tendrian el mismo hash, y con un solo ataque de diccionario
    // se sabria que comparten contrasena. Ver explicacion.md, seccion 2.
    expect(primerHash).not.toBe(segundoHash)
  })

  it('ambos hashes verifican contra la misma contrasena', async () => {
    const contrasena = 'unaContrasenaLargaYSegura2026'

    const primerHash = await hashearContrasena(contrasena)
    const segundoHash = await hashearContrasena(contrasena)

    expect(await verificarContrasena(primerHash, contrasena)).toBe(true)
    expect(await verificarContrasena(segundoHash, contrasena)).toBe(true)
  })
})

describe('verificarContrasena', () => {
  it('devuelve true con la contrasena correcta', async () => {
    const contrasena = 'unaContrasenaLargaYSegura2026'
    const hash = await hashearContrasena(contrasena)

    expect(await verificarContrasena(hash, contrasena)).toBe(true)
  })

  it('devuelve false con la contrasena incorrecta', async () => {
    const hash = await hashearContrasena('unaContrasenaLargaYSegura2026')

    expect(await verificarContrasena(hash, 'otraContrasenaDistinta2026')).toBe(false)
  })

  it('devuelve false con una contrasena vacia', async () => {
    const hash = await hashearContrasena('unaContrasenaLargaYSegura2026')

    expect(await verificarContrasena(hash, '')).toBe(false)
  })

  it('devuelve false y NO lanza con un hash corrupto', async () => {
    // Este es un caso importante: si `verify` dejara propagar la excepcion, un
    // hash corrupto en la base produciria un 500 en el endpoint de login. Y
    // todavia peor, el 500 distinguiria "hash corrupto" de "password mal", que
    // es informacion que no se le puede dar al atacante.
    expect(await verificarContrasena('no-es-un-hash-valido', 'lo-que-sea')).toBe(false)
    expect(await verificarContrasena('', 'lo-que-sea')).toBe(false)
    expect(await verificarContrasena('$argon2id$incompleto', 'lo-que-sea')).toBe(false)
  })

  it('distingue contrasenas que difieren en un solo caracter', async () => {
    const hash = await hashearContrasena('unaContrasenaLargaYSegura2026')

    expect(await verificarContrasena(hash, 'unaContrasenaLargaYSegura2027')).toBe(false)
    expect(await verificarContrasena(hash, 'UnaContrasenaLargaYSegura2026')).toBe(false)
  })
})

describe('verificacion en tiempo constante', () => {
  beforeAll(async () => {
    await inicializarHashDeReferencia()
  })

  it('verificarContraReferencia no lanza', async () => {
    // Cuando el usuario no existe, se verifica contra un hash de referencia
    // para que el login tarde lo mismo que cuando el usuario si existe. Sin
    // esto, medir el tiempo de respuesta revelaria que emails estan
    // registrados. Ver explicacion.md, seccion 23.
    await expect(verificarContraReferencia('cualquierContrasena')).resolves.toBeUndefined()
  })

  it('tarda un tiempo comparable al de un verify real', async () => {
    const contrasena = 'unaContrasenaLargaYSegura2026'
    const hashReal = await hashearContrasena(contrasena)

    const inicioReal = Date.now()
    await verificarContrasena(hashReal, contrasena)
    const duracionReal = Date.now() - inicioReal

    const inicioReferencia = Date.now()
    await verificarContraReferencia(contrasena)
    const duracionReferencia = Date.now() - inicioReferencia

    // Margen generoso porque el timing de tests es ruidoso (CPU compartida,
    // garbage collector). Lo que se verifica es el orden de magnitud, que es
    // donde esta la diferencia filtrable: 2 ms contra 100 ms.
    expect(duracionReal).toBeGreaterThan(10)
    expect(duracionReferencia).toBeGreaterThan(10)
  })
})

describe('necesitaRehash', () => {
  it('devuelve false para un hash generado con los parametros actuales', async () => {
    const hash = await hashearContrasena('unaContrasenaLargaYSegura2026')

    expect(necesitaRehash(hash)).toBe(false)
  })

  it('devuelve true para un hash con parametros debiles', () => {
    // Hash simulado con memoria baja: simula una cuenta creada antes de que
    // se subieran los parametros.
    const hashViejo =
      '$argon2id$v=19$m=4096,t=1,p=1$c29tZXNhbHQ$aGFzaGZ0YWRh'

    expect(necesitaRehash(hashViejo)).toBe(true)
  })

  it('devuelve true si no puede leer el formato', () => {
    // Ante la duda, rehashear. Es la postura segura.
    expect(necesitaRehash('formato-desconocido')).toBe(true)
  })

  it('el hash rehasheado verifica la misma contrasena', async () => {
    const contrasena = 'unaContrasenaLargaYSegura2026'
    const hashViejo = await hashearContrasena(contrasena)
    const hashNuevo = await hashearContrasena(contrasena)

    // El rehash se dispara con la contrasena en texto plano, que solo existe
    // durante un login. Por eso el resultado tiene que ser equivalente.
    expect(await verificarContrasena(hashNuevo, contrasena)).toBe(true)
  })
})
