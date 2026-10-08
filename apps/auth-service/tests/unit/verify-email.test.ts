import { beforeEach, describe, expect, it } from 'vitest'
import { AppError } from '../../src/lib/errors.js'
import { generarTokenDeUnSoloUso } from '../../src/modules/users/one-time-token.js'
import { canjearVerificacionDeEmail } from '../../src/modules/auth/verify-email.js'
import { crearFakesDeMemoria, type FakesDeMemoria } from '../helpers/fakes.js'

function contexto() {
  return { requestId: 'req-verificacion', ip: '203.0.113.9' }
}

function sembrarToken(
  fakes: FakesDeMemoria,
  userId: string,
  purpose: 'email_verification' | 'password_reset' = 'email_verification',
  ahora = new Date(),
) {
  const emitido = generarTokenDeUnSoloUso(purpose, ahora)
  void fakes.tokens.guardar({
    userId,
    purpose: emitido.purpose,
    tokenHash: emitido.tokenHash,
    expiresAt: emitido.expiresAt,
  })
  return emitido
}

describe('canjearVerificacionDeEmail', () => {
  let fakes: FakesDeMemoria

  beforeEach(() => {
    fakes = crearFakesDeMemoria()
  })

  it('marca el token como usado y verifica el email', async () => {
    const usuario = await fakes.usuarios.crear({ email: 'ana@example.com', passwordHash: 'x' })
    const emitido = sembrarToken(fakes, usuario.id)

    await canjearVerificacionDeEmail(
      { usuarios: fakes.usuarios, tokens: fakes.tokens, auditoria: fakes.auditoria },
      emitido.token,
      contexto(),
    )

    expect(fakes.tokensInternos.get(emitido.tokenHash)?.usedAt).not.toBeNull()
    expect(fakes.usuariosInternos.get('ana@example.com')?.emailVerifiedAt).not.toBeNull()
    expect(fakes.eventos.map((e) => e.tipo)).toContain('email_verificado')
  })

  it('rechaza un token inexistente y no modifica al usuario', async () => {
    const usuario = await fakes.usuarios.crear({ email: 'bea@example.com', passwordHash: 'x' })

    const promesa = canjearVerificacionDeEmail(
      { usuarios: fakes.usuarios, tokens: fakes.tokens, auditoria: fakes.auditoria },
      'token-que-no-existe',
      contexto(),
    )

    await expect(promesa).rejects.toSatisfy(
      (error: unknown) => error instanceof AppError && error.code === 'invalid_credentials',
    )
    expect(fakes.usuariosInternos.get('bea@example.com')?.emailVerifiedAt).toBeNull()
    expect(fakes.eventos.some((e) => e.tipo === 'verificacion_fallida')).toBe(true)
  })

  it('rechaza un token ya usado', async () => {
    const usuario = await fakes.usuarios.crear({ email: 'caro@example.com', passwordHash: 'x' })
    const emitido = sembrarToken(fakes, usuario.id)
    await fakes.tokens.marcarUsado({ tokenHash: emitido.tokenHash, usadoEn: new Date() })

    const promesa = canjearVerificacionDeEmail(
      { usuarios: fakes.usuarios, tokens: fakes.tokens, auditoria: fakes.auditoria },
      emitido.token,
      contexto(),
    )

    await expect(promesa).rejects.toBeInstanceOf(AppError)
    expect(fakes.eventos.some((e) => e.tipo === 'verificacion_fallida')).toBe(true)
  })

  it('rechaza un token expirado', async () => {
    const usuario = await fakes.usuarios.crear({ email: 'dani@example.com', passwordHash: 'x' })
    const emitido = sembrarToken(fakes, usuario.id, 'email_verification', new Date('2020-01-01T00:00:00.000Z'))

    const promesa = canjearVerificacionDeEmail(
      { usuarios: fakes.usuarios, tokens: fakes.tokens, auditoria: fakes.auditoria },
      emitido.token,
      contexto(),
    )

    await expect(promesa).rejects.toBeInstanceOf(AppError)
  })

  it('rechaza un token que no es de verificacion de email', async () => {
    const usuario = await fakes.usuarios.crear({ email: 'emi@example.com', passwordHash: 'x' })
    const emitido = sembrarToken(fakes, usuario.id, 'password_reset')

    const promesa = canjearVerificacionDeEmail(
      { usuarios: fakes.usuarios, tokens: fakes.tokens, auditoria: fakes.auditoria },
      emitido.token,
      contexto(),
    )

    await expect(promesa).rejects.toBeInstanceOf(AppError)
  })

  it('no puede canjearse dos veces aunque llamen en paralelo', async () => {
    const usuario = await fakes.usuarios.crear({ email: 'flor@example.com', passwordHash: 'x' })
    const emitido = sembrarToken(fakes, usuario.id)

    const promesaDos = Promise.allSettled([
      canjearVerificacionDeEmail(
        { usuarios: fakes.usuarios, tokens: fakes.tokens, auditoria: fakes.auditoria },
        emitido.token,
      ),
      canjearVerificacionDeEmail(
        { usuarios: fakes.usuarios, tokens: fakes.tokens, auditoria: fakes.auditoria },
        emitido.token,
      ),
    ])

    const resultados = await promesaDos
    expect(resultados.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
    expect(resultados.filter((r) => r.status === 'rejected')).toHaveLength(1)
  })
})