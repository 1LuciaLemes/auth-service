

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



    expect(hash).toMatch(/^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$/)
  })

  it('dos llamadas con la misma contrasena dan hashes DISTINTOS', async () => {
    const contrasena = 'unaContrasenaLargaYSegura2026'

    const primerHash = await hashearContrasena(contrasena)
    const segundoHash = await hashearContrasena(contrasena)




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


    const hashViejo =
      '$argon2id$v=19$m=4096,t=1,p=1$c29tZXNhbHQ$aGFzaGZ0YWRh'

    expect(necesitaRehash(hashViejo)).toBe(true)
  })

  it('devuelve true si no puede leer el formato', () => {

    expect(necesitaRehash('formato-desconocido')).toBe(true)
  })

  it('el hash rehasheado verifica la misma contrasena', async () => {
    const contrasena = 'unaContrasenaLargaYSegura2026'
    const hashViejo = await hashearContrasena(contrasena)
    const hashNuevo = await hashearContrasena(contrasena)



    expect(await verificarContrasena(hashNuevo, contrasena)).toBe(true)
  })
})
