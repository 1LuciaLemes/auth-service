import { randomUUID } from 'node:crypto'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import type { Pool } from 'pg'
import type { NodePgDatabase } from 'drizzle-orm/node-postgres'
import * as schema from '../../src/db/schema.js'
import { refreshTokens } from '../../src/db/schema.js'
import { crearRepositorioUsuarios } from '../../src/db/repositories/usuarios.js'
import type { RepositorioUsuarios } from '../../src/modules/auth/ports.js'
import { crearDbDePrueba, hayBaseDePrueba } from '../helpers/postgres.js'

describe.skipIf(!hayBaseDePrueba)('RepositorioUsuarios contra Postgres', () => {
  let pool: Pool
  let db: NodePgDatabase<typeof schema>
  let usuarios: RepositorioUsuarios

  beforeAll(() => {
    const contexto = crearDbDePrueba()
    pool = contexto.pool
    db = contexto.db
    usuarios = crearRepositorioUsuarios(db)
  })

  afterAll(async () => {
    await pool.end()
  })

  beforeEach(async () => {
    await pool.query('TRUNCATE users RESTART IDENTITY CASCADE')
  })

  it('crear guarda el usuario y buscarPorEmail lo devuelve activo y sin verificar', async () => {
    const creado = await usuarios.crear({ email: 'ana@example.com', passwordHash: 'hash-ana' })

    expect(creado.email).toBe('ana@example.com')
    expect(creado.id).toBeTruthy()

    const encontrado = await usuarios.buscarPorEmail('ana@example.com')
    expect(encontrado.encontrado).toBe(true)
    if (!encontrado.encontrado) return
    expect(encontrado.id).toBe(creado.id)
    expect(encontrado.passwordHash).toBe('hash-ana')
    expect(encontrado.emailVerifiedAt).toBeNull()
    expect(encontrado.role).toBe('user')
    expect(encontrado.status).toBe('active')
    expect(encontrado.estado).toEqual({ intentosFallidos: 0, bloqueadaHasta: null })
  })

  it('buscarPorEmail devuelve {encontrado:false} si el email no existe', async () => {
    const resultado = await usuarios.buscarPorEmail('nadie@example.com')

    expect(resultado).toEqual({ encontrado: false })
  })

  it('buscarPorId devuelve null si el usuario no existe', async () => {
    const resultado = await usuarios.buscarPorId('00000000-0000-0000-0000-000000000000')

    expect(resultado).toBeNull()
  })

  it('crear con un email repetido lanza la violacion de unicidad (23505)', async () => {
    await usuarios.crear({ email: 'duplicado@example.com', passwordHash: 'h1' })

    await expect(
      usuarios.crear({ email: 'duplicado@example.com', passwordHash: 'h2' }),
    ).rejects.toMatchObject({ code: '23505' })
  })

  it('actualizarBloqueo persiste los intentos y la fecha de bloqueo', async () => {
    const creado = await usuarios.crear({ email: 'bloqueo@example.com', passwordHash: 'h' })
    const hasta = new Date(Date.now() + 15 * 60 * 1000)

    await usuarios.actualizarBloqueo(creado.id, { intentosFallidos: 3, bloqueadaHasta: hasta })
    const encontrado = await usuarios.buscarPorId(creado.id)

    expect(encontrado?.estado.intentosFallidos).toBe(3)
    expect(encontrado?.estado.bloqueadaHasta?.getTime()).toBe(hasta.getTime())
  })

  it('limpiarBloqueo resetea los intentos y la fecha', async () => {
    const creado = await usuarios.crear({ email: 'limpio@example.com', passwordHash: 'h' })
    await usuarios.actualizarBloqueo(creado.id, { intentosFallidos: 5, bloqueadaHasta: new Date() })

    await usuarios.limpiarBloqueo(creado.id)
    const encontrado = await usuarios.buscarPorId(creado.id)

    expect(encontrado?.estado).toEqual({ intentosFallidos: 0, bloqueadaHasta: null })
  })

  it('marcarEmailVerificado setea la fecha de verificacion', async () => {
    const creado = await usuarios.crear({ email: 'verifica@example.com', passwordHash: 'h' })
    const instante = new Date()

    await usuarios.marcarEmailVerificado(creado.id, instante)
    const encontrado = await usuarios.buscarPorId(creado.id)

    expect(encontrado?.emailVerifiedAt?.getTime()).toBe(instante.getTime())
  })

  it('actualizarContrasena reemplaza el hash', async () => {
    const creado = await usuarios.crear({ email: 'clave@example.com', passwordHash: 'viejo' })

    await usuarios.actualizarContrasena(creado.id, 'nuevo')
    const encontrado = await usuarios.buscarPorId(creado.id)

    expect(encontrado?.passwordHash).toBe('nuevo')
  })

  it('revocarRefreshTokens marca los vigentes y devuelve cuantos', async () => {
    const creado = await usuarios.crear({ email: 'revoca@example.com', passwordHash: 'h' })
    const vence = new Date(Date.now() + 1_000_000)
    await db.insert(refreshTokens).values([
      { userId: creado.id, familyId: randomUUID(), tokenHash: 'tok-1', expiresAt: vence },
      { userId: creado.id, familyId: randomUUID(), tokenHash: 'tok-2', expiresAt: vence },
    ])

    const revocados = await usuarios.revocarRefreshTokens(creado.id, 'password_reset', new Date())

    expect(revocados).toBe(2)
    const filas = await db.select().from(refreshTokens)
    expect(filas.every((f) => f.revokedReason === 'password_reset')).toBe(true)
    expect(filas.every((f) => f.revokedAt !== null)).toBe(true)
  })

  it('revocarRefreshTokens no cuenta los tokens ya revocados', async () => {
    const creado = await usuarios.crear({ email: 'revoca2@example.com', passwordHash: 'h' })
    await db.insert(refreshTokens).values({
      userId: creado.id,
      familyId: randomUUID(),
      tokenHash: 'tok-r',
      expiresAt: new Date(Date.now() + 1000_000),
      revokedAt: new Date(),
      revokedReason: 'manual',
    })

    const revocados = await usuarios.revocarRefreshTokens(creado.id, 'password_reset', new Date())

    expect(revocados).toBe(0)
  })
})
