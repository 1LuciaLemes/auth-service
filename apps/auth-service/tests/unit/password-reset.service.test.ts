

import { beforeEach, describe, expect, it } from 'vitest'
import {
  MENSAJE_RESET_GENERICO,
  completarResetDeContrasena,
  solicitarResetDeContrasena,
  type DependenciasReset,
} from '../../src/modules/users/password-reset.service.js'
import { hashearToken } from '../../src/modules/users/one-time-token.js'
import { validarContrasena } from '../../src/lib/password-policy.js'
import type {
  EventoAuditoria,
  RepositorioAuditoria,
  RepositorioOneTimeTokens,
  RepositorioUsuarios,
} from '../../src/modules/auth/ports.js'

const CONTRASENA_VALIDA = 'EstaEsLaContrasenaDelUsuario1!'


interface FilaToken {
  userId: string
  purpose: string
  tokenHash: string
  expiresAt: Date
  usedAt: Date | null
}

function crearBase(tokensIniciales: FilaToken[] = []) {
  const filas = new Map<string, FilaToken>(tokensIniciales.map((f) => [f.tokenHash, f]))
  const usuarios = new Map<string, { id: string; email: string; passwordHash: string | null; status: string; role: 'user' | 'admin'; emailVerifiedAt: Date | null }>()
  const eventos: EventoAuditoria[] = []
  const emails: { email: string; token: string; expiraEnMinutos: number }[] = []
  const refreshRevocados: { userId: string; motivo: string }[] = []

  const repoUsuarios: RepositorioUsuarios = {
    buscarPorEmail: async (email) => {
      const u = [...usuarios.values()].find((x) => x.email === email)
      return u
        ? {
            encontrado: true,
            id: u.id,
            email: u.email,
            passwordHash: u.passwordHash,
            emailVerifiedAt: u.emailVerifiedAt,
            role: u.role,
            estado: { intentosFallidos: 0, bloqueadoHasta: null },
            status: u.status as 'active',
          }
        : { encontrado: false }
    },
    buscarPorId: async (id) => {
      const u = usuarios.get(id)
      if (!u) return null
      return {
        encontrado: true,
        id: u.id,
        email: u.email,
        passwordHash: u.passwordHash,
        emailVerifiedAt: u.emailVerifiedAt,
        role: u.role,
        estado: { intentosFallidos: 0, bloqueadoHasta: null },
        status: u.status as 'active',
      }
    },
    crear: async ({ email, passwordHash, displayName }) => {
      void displayName
      const id = `usr_${usuarios.size + 1}`
      usuarios.set(id, {
        id,
        email,
        passwordHash,
        status: 'active',
        role: 'user',
        emailVerifiedAt: null,
      })
      return { id, email }
    },
    actualizarBloqueo: async () => undefined,
    limpiarBloqueo: async () => undefined,
    marcarEmailVerificado: async (id, instante) => {
      const u = usuarios.get(id)
      if (u) u.emailVerifiedAt = instante
    },
    actualizarContrasena: async (id, passwordHash) => {
      const u = usuarios.get(id)
      if (u) u.passwordHash = passwordHash
    },
    revocarRefreshTokens: async (id, motivo) => {
      refreshRevocados.push({ userId: id, motivo })
      return 2
    },
  }

  const repoTokens: RepositorioOneTimeTokens = {
    guardar: async ({ userId, purpose, tokenHash, expiresAt }) => {


      for (const [clave, fila] of filas) {
        if (fila.userId === userId && fila.purpose === purpose && fila.usedAt === null) {
          filas.delete(clave)
        }
      }
      filas.set(tokenHash, { userId, purpose, tokenHash, expiresAt, usedAt: null })
    },
    buscarPorHash: async (tokenHash) => filas.get(tokenHash) ?? null,
    marcarUsado: async ({ tokenHash, usadoEn }) => {
      const fila = filas.get(tokenHash)
      if (!fila || fila.usedAt !== null) return 0
      fila.usedAt = usadoEn
      return 1
    },
  }

  const repoAuditoria: RepositorioAuditoria = {
    registrar: async (evento) => {
      eventos.push(evento)
    },
  }

  return { filas, usuarios, eventos, emails, refreshRevocados, repoUsuarios, repoTokens, repoAuditoria }
}

let base: ReturnType<typeof crearBase>
let deps: DependenciasReset

beforeEach(async () => {
  base = crearBase()
  deps = {
    usuarios: base.repoUsuarios,
    tokens: base.repoTokens,
    auditoria: base.repoAuditoria,
    enviarEmailDeReset: async (params) => {
      base.emails.push(params)
    },
    appUrl: 'https://auth.test',
  }
})


async function crearUsuario(email = 'lucia@ejemplo.com') {
  return base.repoUsuarios.crear({ email, passwordHash: 'hash-original', displayName: 'Lucia' })
}

describe('solicitarResetDeContrasena', () => {
  it('manda el email con un token en claro, no el hash', async () => {
    await crearUsuario()
    await solicitarResetDeContrasena(deps, { email: 'lucia@ejemplo.com' })

    expect(base.emails).toHaveLength(1)
    const [{ token }] = base.emails



    const fila = [...base.filas.values()][0]
    expect(token).not.toBe(fila.tokenHash)
    expect(fila.tokenHash).toBe(hashearToken(token))
  })

  it('el token guardado caduca en 15 minutos', async () => {
    await crearUsuario()
    await solicitarResetDeContrasena(deps, { email: 'lucia@ejemplo.com' })

    const fila = [...base.filas.values()][0]
    const minutos = (fila.expiresAt.getTime() - Date.now()) / 60_000


    expect(minutos).toBeGreaterThan(14)
    expect(minutos).toBeLessThanOrEqual(15)
  })

  it('el email se busca normalizado, con mayusculas o sin ellas', async () => {
    await crearUsuario('lucia@ejemplo.com')
    await solicitarResetDeContrasena(deps, { email: 'LUCIA@Ejemplo.COM' })




    expect(base.emails).toHaveLength(1)
  })

  it('NO envia email a un email inexistente, pero tampoco dice que no existe', async () => {
    const resultado = await solicitarResetDeContrasena(deps, { email: 'nadie@ejemplo.com' })

    expect(base.emails).toHaveLength(0)


    expect(resultado).toBeUndefined()
  })

  it('el mismo mensaje para email existente y para inexistente', async () => {



    expect(MENSAJE_RESET_GENERICO).toContain('Si esa direccion esta registrada')
  })

  it('audita los DOS caminos, para que el log no sea un registro de que emails existen', async () => {
    await crearUsuario()

    await solicitarResetDeContrasena(deps, { email: 'lucia@ejemplo.com' })
    await solicitarResetDeContrasena(deps, { email: 'nadie@ejemplo.com' })



    expect(base.eventos.map((e) => e.tipo)).toContain('reset_solicitado')
    expect(base.eventos.map((e) => e.tipo)).toContain('reset_solicitado_email_inexistente')
  })

  it('invalida el token anterior si se pide un segundo reset', async () => {
    await crearUsuario()

    await solicitarResetDeContrasena(deps, { email: 'lucia@ejemplo.com' })
    const primerToken = base.emails[0].token
    await solicitarResetDeContrasena(deps, { email: 'lucia@ejemplo.com' })
    const segundoToken = base.emails[1].token



    expect(base.filas.size).toBe(1)
    expect(base.filas.has(hashearToken(primerToken))).toBe(false)
    expect(base.filas.has(hashearToken(segundoToken))).toBe(true)
  })

  it('no pide reset para una cuenta deshabilitada', async () => {
    const creado = await crearUsuario()
    base.usuarios.get(creado.id)!.status = 'disabled'

    await solicitarResetDeContrasena(deps, { email: 'lucia@ejemplo.com' })



    expect(base.emails).toHaveLength(0)
    expect(base.eventos.map((e) => e.tipo)).toContain('reset_solicitado_cuenta_no_activa')
  })

  it('no manda el email si no se pudo guardar el token', async () => {
    await crearUsuario()
    const depsCaidos: DependenciasReset = {
      ...deps,
      tokens: {
        ...base.repoTokens,
        guardar: async () => {
          throw new Error('connection terminated')
        },
      },
    }

    await expect(
      solicitarResetDeContrasena(depsCaidos, { email: 'lucia@ejemplo.com' }),
    ).rejects.toMatchObject({ statusCode: 500 })



    expect(base.emails).toHaveLength(0)
  })
})

describe('completarResetDeContrasena', () => {

  async function pedirTokenYDevolverlo(email = 'lucia@ejemplo.com') {
    await crearUsuario(email)
    await solicitarResetDeContrasena(deps, { email })
    return base.emails[0].token
  }

  it('cambia la contrasena y devuelve el userId', async () => {
    const token = await pedirTokenYDevolverlo()
    const hashAntes = base.usuarios.get('usr_1')!.passwordHash

    const resultado = await completarResetDeContrasena(deps, {
      token,
      nuevaContrasena: 'NuevaContrasenaSegura123!',
    })

    expect(resultado.userId).toBe('usr_1')

    expect(base.usuarios.get('usr_1')!.passwordHash).not.toBe(hashAntes)
    expect(base.usuarios.get('usr_1')!.passwordHash).toMatch(/^\$argon2/)
  })

  it('revoca las sesiones abiertas, que es lo que protege el reset', async () => {
    const token = await pedirTokenYDevolverlo()

    await completarResetDeContrasena(deps, { token, nuevaContrasena: 'NuevaContrasenaSegura123!' })



    expect(base.refreshRevocados).toEqual([{ userId: 'usr_1', motivo: 'password_reset' }])
  })

  it('el token queda marcado como usado', async () => {
    const token = await pedirTokenYDevolverlo()

    await completarResetDeContrasena(deps, { token, nuevaContrasena: 'NuevaContrasenaSegura123!' })

    expect([...base.filas.values()][0].usedAt).not.toBeNull()
  })

  it('NO acepta el mismo token dos veces', async () => {
    const token = await pedirTokenYDevolverlo()
    await completarResetDeContrasena(deps, { token, nuevaContrasena: 'NuevaContrasenaSegura123!' })



    await expect(
      completarResetDeContrasena(deps, { token, nuevaContrasena: 'OtraContrasenaDistinta1!' }),
    ).rejects.toMatchObject({ statusCode: 401 })
  })

  it('el canje condicional detecta la carrera aunque decidirCanje diga que vale', async () => {










    const token = await pedirTokenYDevolverlo()

    const depsEnCarrera: DependenciasReset = {
      ...deps,
      tokens: {
        ...base.repoTokens,

        marcarUsado: async () => 0,
      },
    }

    await expect(
      completarResetDeContrasena(depsEnCarrera, { token, nuevaContrasena: 'NuevaContrasenaSegura123!' }),
    ).rejects.toMatchObject({ statusCode: 401 })




    expect(base.usuarios.get('usr_1')!.passwordHash).toBe('hash-original')
    expect(base.refreshRevocados).toHaveLength(0)
  })

  it('audita la carrera como un fallo de canje', async () => {
    const token = await pedirTokenYDevolverlo()
    const depsEnCarrera: DependenciasReset = {
      ...deps,
      tokens: { ...base.repoTokens, marcarUsado: async () => 0 },
    }

    await completarResetDeContrasena(depsEnCarrera, {
      token,
      nuevaContrasena: 'NuevaContrasenaSegura123!',
    }).catch(() => undefined)



    expect(base.eventos.some((e) => e.tipo === 'reset_fallido')).toBe(true)
  })

  it('rechaza un token inexistente con el mismo mensaje que uno ya usado', async () => {
    await crearUsuario()
    const token = await pedirTokenYDevolverlo()
    await completarResetDeContrasena(deps, { token, nuevaContrasena: 'NuevaContrasenaSegura123!' })

    const mensajes: string[] = []
    for (const t of [token, 'token-que-no-existe']) {
      try {
        await completarResetDeContrasena(deps, { token: t, nuevaContrasena: 'NuevaContrasenaSegura123!' })
      } catch (error) {
        mensajes.push((error as Error).message)
      }
    }



    expect(mensajes).toHaveLength(2)
    expect(mensajes[0]).toBe(mensajes[1])
  })

  it('rechaza un token de verificacion de email', async () => {


    await crearUsuario()
    base.filas.set('hash-cualquiera', {
      userId: 'usr_1',
      purpose: 'email_verification',
      tokenHash: 'hash-cualquiera',
      expiresAt: new Date(Date.now() + 60_000),
      usedAt: null,
    })

    await expect(
      completarResetDeContrasena(deps, {
        token: 'token-en-claro-cuyo-hash-es-ese',
        nuevaContrasena: 'NuevaContrasenaSegura123!',
      }),
    ).rejects.toMatchObject({ statusCode: 401 })
  })

  it('rechaza un token expirado', async () => {
    await crearUsuario()
    base.filas.set('hash-expirado', {
      userId: 'usr_1',
      purpose: 'password_reset',
      tokenHash: 'hash-expirado',
      expiresAt: new Date(Date.now() - 1000),
      usedAt: null,
    })

    await expect(
      completarResetDeContrasena(deps, {
        token: 'token-vencido',
        nuevaContrasena: 'NuevaContrasenaSegura123!',
      }),
    ).rejects.toMatchObject({ statusCode: 401 })
  })

  it('rechaza una contrasena debil con 400 y la lista de problemas', async () => {
    const token = await pedirTokenYDevolverlo()



    await expect(
      completarResetDeContrasena(deps, { token, nuevaContrasena: 'corta' }),
    ).rejects.toMatchObject({ statusCode: 400, code: 'validation_error' })
  })

  it('un 400 por contrasena debil NO consume el token', async () => {
    const token = await pedirTokenYDevolverlo()

    await completarResetDeContrasena(deps, { token, nuevaContrasena: 'corta' }).catch(() => undefined)



    expect([...base.filas.values()][0].usedAt).toBeNull()



    await expect(
      completarResetDeContrasena(deps, { token, nuevaContrasena: 'NuevaContrasenaSegura123!' }),
    ).resolves.toMatchObject({ userId: 'usr_1' })
  })

  it('rechaza el canje si la cuenta ya no esta activa', async () => {
    const token = await pedirTokenYDevolverlo()
    base.usuarios.get('usr_1')!.status = 'disabled'

    await expect(
      completarResetDeContrasena(deps, { token, nuevaContrasena: 'NuevaContrasenaSegura123!' }),
    ).rejects.toMatchObject({ statusCode: 401 })




    expect([...base.filas.values()][0].usedAt).not.toBeNull()
  })

  it('rechaza un token valido cuyo usuario ya no existe', async () => {
    const token = await pedirTokenYDevolverlo()
    base.usuarios.clear()

    await expect(
      completarResetDeContrasena(deps, { token, nuevaContrasena: 'NuevaContrasenaSegura123!' }),
    ).rejects.toMatchObject({ statusCode: 401 })




    expect([...base.filas.values()][0].usedAt).not.toBeNull()
  })

  it('nunca escribe la contrasena ni el token en el audit log', async () => {
    const token = await pedirTokenYDevolverlo()
    await completarResetDeContrasena(deps, { token, nuevaContrasena: 'NuevaContrasenaSegura123!' })

    const serializado = JSON.stringify(base.eventos)

    expect(serializado).not.toContain('NuevaContrasenaSegura123!')
    expect(serializado).not.toContain(token)

    expect(serializado).not.toContain(hashearToken(token))
  })

  it('acepta cualquier contrasena que pase la politica, sin requisitos extra', async () => {
    const token = await pedirTokenYDevolverlo()



    const contrasena = 'CambioDeContrasena1!'
    expect(validarContrasena(contrasena).valida).toBe(true)

    await expect(
      completarResetDeContrasena(deps, { token, nuevaContrasena: contrasena }),
    ).resolves.toMatchObject({ userId: 'usr_1' })
  })
})
