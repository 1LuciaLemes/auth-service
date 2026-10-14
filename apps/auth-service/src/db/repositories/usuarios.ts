import { and, eq, isNull } from 'drizzle-orm'
import type { NodePgDatabase } from 'drizzle-orm/node-postgres'
import * as schema from '../schema.js'
import { refreshTokens, users } from '../schema.js'
import type { EstadoBloqueo } from '../../modules/auth/lockout.js'
import type { RepositorioUsuarios, ResultadoBusqueda } from '../../modules/auth/ports.js'

type Db = NodePgDatabase<typeof schema>

type UsuarioEncontrado = ResultadoBusqueda & { encontrado: true }

function causaOriginal(error: unknown): unknown {
  if (error !== null && typeof error === 'object' && 'cause' in error) {
    const causa = (error as { cause?: unknown }).cause
    if (causa !== undefined && causa !== null) return causa
  }
  return error
}

function aResultado(fila: typeof users.$inferSelect): UsuarioEncontrado {
  return {
    encontrado: true,
    id: fila.id,
    email: fila.email,
    passwordHash: fila.passwordHash,
    emailVerifiedAt: fila.emailVerifiedAt,
    role: fila.role,
    estado: {
      intentosFallidos: fila.failedLoginAttempts,
      bloqueadaHasta: fila.lockedUntil,
    },
    status: fila.status,
  }
}

export function crearRepositorioUsuarios(db: Db): RepositorioUsuarios {
  return {
    async buscarPorEmail(email) {
      const filas = await db.select().from(users).where(eq(users.email, email)).limit(1)
      const fila = filas[0]
      return fila ? aResultado(fila) : { encontrado: false }
    },

    async buscarPorId(id) {
      const filas = await db.select().from(users).where(eq(users.id, id)).limit(1)
      const fila = filas[0]
      return fila ? aResultado(fila) : null
    },

    async crear({ email, passwordHash, displayName }) {
      try {
        const filas = await db
          .insert(users)
          .values({ email, passwordHash, displayName: displayName ?? null })
          .returning({ id: users.id, email: users.email })
        return filas[0]!
      } catch (error) {
        throw causaOriginal(error)
      }
    },

    async actualizarBloqueo(id: string, estado: EstadoBloqueo) {
      await db
        .update(users)
        .set({
          failedLoginAttempts: estado.intentosFallidos,
          lockedUntil: estado.bloqueadaHasta,
          updatedAt: new Date(),
        })
        .where(eq(users.id, id))
    },

    async limpiarBloqueo(id: string) {
      await db
        .update(users)
        .set({ failedLoginAttempts: 0, lockedUntil: null, updatedAt: new Date() })
        .where(eq(users.id, id))
    },

    async marcarEmailVerificado(id: string, instante: Date) {
      await db
        .update(users)
        .set({ emailVerifiedAt: instante, updatedAt: new Date() })
        .where(eq(users.id, id))
    },

    async actualizarContrasena(id: string, passwordHash: string) {
      await db
        .update(users)
        .set({ passwordHash, updatedAt: new Date() })
        .where(eq(users.id, id))
    },

    async revocarRefreshTokens(id: string, motivo: string, instante: Date) {
      const filas = await db
        .update(refreshTokens)
        .set({ revokedAt: instante, revokedReason: motivo })
        .where(and(eq(refreshTokens.userId, id), isNull(refreshTokens.revokedAt)))
        .returning({ id: refreshTokens.id })

      return filas.length
    },
  }
}
