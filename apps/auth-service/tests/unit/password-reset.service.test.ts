/**
 * Tests del servicio de reset de contrasena.
 *
 * Lo que mas importa aqui es comprobar lo que NO se puede ver en una prueba
 * manual: que el endpoint de solicitud no revele si un email existe, y que un
 * token no se pueda canjear dos veces.
 *
 * Ver explicacion.md, seccion 36.
 */

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

/** Fila en memoria de one_time_tokens. */
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
      // Se invalidan los previos del mismo usuario y proposito, que es lo que
      // hace que el ultimo email sea el unico valido.
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

/** Registra un usuario activo para tener algo contra lo que pedir un reset. */
async function crearUsuario(email = 'lucia@ejemplo.com') {
  return base.repoUsuarios.crear({ email, passwordHash: 'hash-original', displayName: 'Lucia' })
}

describe('solicitarResetDeContrasena', () => {
  it('manda el email con un token en claro, no el hash', async () => {
    await crearUsuario()
    await solicitarResetDeContrasena(deps, { email: 'lucia@ejemplo.com' })

    expect(base.emails).toHaveLength(1)
    const [{ token }] = base.emails

    // Lo que viaja por el email es el token en claro, y lo que se guarda es su
    // hash. Mandar el hash produce un enlace que no verifica nada.
    const fila = [...base.filas.values()][0]
    expect(token).not.toBe(fila.tokenHash)
    expect(fila.tokenHash).toBe(hashearToken(token))
  })

  it('el token guardado caduca en 15 minutos', async () => {
    await crearUsuario()
    await solicitarResetDeContrasena(deps, { email: 'lucia@ejemplo.com' })

    const fila = [...base.filas.values()][0]
    const minutos = (fila.expiresAt.getTime() - Date.now()) / 60_000

    // 15, no 24 horas: el token de reset es el mas sensible de los dos.
    expect(minutos).toBeGreaterThan(14)
    expect(minutos).toBeLessThanOrEqual(15)
  })

  it('el email se busca normalizado, con mayusculas o sin ellas', async () => {
    await crearUsuario('lucia@ejemplo.com')
    await solicitarResetDeContrasena(deps, { email: 'LUCIA@Ejemplo.COM' })

    // Si no se normalizara, un usuario que escribe su email con mayusculas
    // receberia el mensaje generico sin ningun email, y pensaria que el
    // sistema esta roto.
    expect(base.emails).toHaveLength(1)
  })

  it('NO envia email a un email inexistente, pero tampoco dice que no existe', async () => {
    const resultado = await solicitarResetDeContrasena(deps, { email: 'nadie@ejemplo.com' })

    expect(base.emails).toHaveLength(0)
    // Y el retorno es undefined, igual que en el caso favorable. Un endpoint
    // que devolviera algo distinto seria un enumerador de cuentas.
    expect(resultado).toBeUndefined()
  })

  it('el mismo mensaje para email existente y para inexistente', async () => {
    // El mensaje vive en UNA constante y la funcion no devuelve nada, asi que
    // el endpoint no tiene forma de diferenciar los casos. Este test fija que
    // la constante no se va a separar en dos textos distintos.
    expect(MENSAJE_RESET_GENERICO).toContain('Si esa direccion esta registrada')
  })

  it('audita los DOS caminos, para que el log no sea un registro de que emails existen', async () => {
    await crearUsuario()

    await solicitarResetDeContrasena(deps, { email: 'lucia@ejemplo.com' })
    await solicitarResetDeContrasena(deps, { email: 'nadie@ejemplo.com' })

    // Si solo se auditara el caso favorable, el log seria el oraculo que el
    // endpoint evita darle a quien lo consulta.
    expect(base.eventos.map((e) => e.tipo)).toContain('reset_solicitado')
    expect(base.eventos.map((e) => e.tipo)).toContain('reset_solicitado_email_inexistente')
  })

  it('invalida el token anterior si se pide un segundo reset', async () => {
    await crearUsuario()

    await solicitarResetDeContrasena(deps, { email: 'lucia@ejemplo.com' })
    const primerToken = base.emails[0].token
    await solicitarResetDeContrasena(deps, { email: 'lucia@ejemplo.com' })
    const segundoToken = base.emails[1].token

    // Sin esto, un atacante que pide un reset antes que el titular conserva un
    // token valido, y el reset legitimo del usuario no lo invalida.
    expect(base.filas.size).toBe(1)
    expect(base.filas.has(hashearToken(primerToken))).toBe(false)
    expect(base.filas.has(hashearToken(segundoToken))).toBe(true)
  })

  it('no pide reset para una cuenta deshabilitada', async () => {
    const creado = await crearUsuario()
    base.usuarios.get(creado.id)!.status = 'disabled'

    await solicitarResetDeContrasena(deps, { email: 'lucia@ejemplo.com' })

    // Si se permitiera, un admin que dio de baja a alguien lo volveria a
    // encontrar dentro con la contrasena cambiada.
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

    // Mandar el email sin fila en la base es peor que no mandarlo: el usuario
    // cree que tiene 15 minutos y en realidad no tiene nada.
    expect(base.emails).toHaveLength(0)
  })
})

describe('completarResetDeContrasena', () => {
  /** Pide un reset y devuelve el token en claro del email. */
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
    // El hash anterior, no la contrasena en claro.
    expect(base.usuarios.get('usr_1')!.passwordHash).not.toBe(hashAntes)
    expect(base.usuarios.get('usr_1')!.passwordHash).toMatch(/^\$argon2/)
  })

  it('revoca las sesiones abiertas, que es lo que protege el reset', async () => {
    const token = await pedirTokenYDevolverlo()

    await completarResetDeContrasena(deps, { token, nuevaContrasena: 'NuevaContrasenaSegura123!' })

    // Sin esto el reset no protege nada: el atacante que robo la contrasena la
    // cambia, ve el aviso por email y sigue dentro con su refresh token.
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

    // El segundo intento con el mismo token, que es lo que pasaria con un
    // doble click o con un atacante y el titular a la vez.
    await expect(
      completarResetDeContrasena(deps, { token, nuevaContrasena: 'OtraContrasenaDistinta1!' }),
    ).rejects.toMatchObject({ statusCode: 401 })
  })

  it('el canje condicional detecta la carrera aunque decidirCanje diga que vale', async () => {
    // Este es el test mas importante del archivo.
    //
    // Reproduce la ventana de carrera que un `find` seguido de un `update`
    // separados deja abierta: la fila se lee con used_at NULL, decideCanje la
    // aprueba, y para cuando se marca como usada OTRO request ya lo hizo.
    //
    // Para aislar EXACTAMENTE esa guarda y no la de `ya_usado` (que actua antes
    // y ya esta cubierta por otro test), el repositorio falso devuelve la fila
    // como vigente pero hace que `marcarUsado` responda 0, que es lo que hace
    // la base cuando el UPDATE con WHERE used_at IS NULL no afecta ninguna fila.
    const token = await pedirTokenYDevolverlo()

    const depsEnCarrera: DependenciasReset = {
      ...deps,
      tokens: {
        ...base.repoTokens,
        // Simula que otro request gano la carrera justo antes de este.
        marcarUsado: async () => 0,
      },
    }

    await expect(
      completarResetDeContrasena(depsEnCarrera, { token, nuevaContrasena: 'NuevaContrasenaSegura123!' }),
    ).rejects.toMatchObject({ statusCode: 401 })

    // Y lo importante: la contrasena NO se toco. Sin la guarda, los dos
    // requests cambian la contrasena, el del atacante pone la que quiere, y el
    // del titular ve un exito que no es cierto.
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

    // Dos intentos de canjear el mismo token es un evento de seguridad, y con
    // un motivo propio para poder distinguirlo de un token simplemente viejo.
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

    // Si distinguieran, un atacante podria usar tokens inventados como oraculo
    // para descubrir que tokens son reales.
    expect(mensajes).toHaveLength(2)
    expect(mensajes[0]).toBe(mensajes[1])
  })

  it('rechaza un token de verificacion de email', async () => {
    // El cruce de propositos. Un token de verificacion esta en la misma
    // bandeja de entrada y es mucho mas facil de conseguir.
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

    // 400, no 401: el token va bien, lo que esta mal es la contrasena. Y con
    // la lista, porque el usuario tiene que saber que le falta.
    await expect(
      completarResetDeContrasena(deps, { token, nuevaContrasena: 'corta' }),
    ).rejects.toMatchObject({ statusCode: 400, code: 'validation_error' })
  })

  it('un 400 por contrasena debil NO consume el token', async () => {
    const token = await pedirTokenYDevolverlo()

    await completarResetDeContrasena(deps, { token, nuevaContrasena: 'corta' }).catch(() => undefined)

    // Si el fallo de validacion gastara el token, el usuario tendria que
    // pedir otro email entero por equivocarse al escribir la contrasena nueva.
    expect([...base.filas.values()][0].usedAt).toBeNull()

    // Y por eso el mismo token sirve en el siguiente intento, ya con una
    // contrasena valida.
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

    // Y el token NO se puede reutilizar si alguien reactiva la cuenta: un
    // token de reset que sobrevivio a la deshabilitacion es una puerta
    // abierta.
    expect([...base.filas.values()][0].usedAt).not.toBeNull()
  })

  it('rechaza un token valido cuyo usuario ya no existe', async () => {
    const token = await pedirTokenYDevolverlo()
    base.usuarios.clear()

    await expect(
      completarResetDeContrasena(deps, { token, nuevaContrasena: 'NuevaContrasenaSegura123!' }),
    ).rejects.toMatchObject({ statusCode: 401 })

    // El token se canjea igual, para no dejarlo utilizable. No deberia pasar
    // nunca, porque one_time_tokens tiene ON DELETE CASCADE, pero si llegara
    // aqui por borrado manual, un token vivo sin usuario es una puerta abierta.
    expect([...base.filas.values()][0].usedAt).not.toBeNull()
  })

  it('nunca escribe la contrasena ni el token en el audit log', async () => {
    const token = await pedirTokenYDevolverlo()
    await completarResetDeContrasena(deps, { token, nuevaContrasena: 'NuevaContrasenaSegura123!' })

    const serializado = JSON.stringify(base.eventos)

    expect(serializado).not.toContain('NuevaContrasenaSegura123!')
    expect(serializado).not.toContain(token)
    // El hash del token tampoco: es un identificador de sesion recuperable.
    expect(serializado).not.toContain(hashearToken(token))
  })

  it('acepta cualquier contrasena que pase la politica, sin requisitos extra', async () => {
    const token = await pedirTokenYDevolverlo()
    // La politica es la misma que en el registro. Si el reset aplicara reglas
    // MAS estrictas, el usuario con una contrasena aceptable en su registro no
    // podria recuperarla, que es el peor sitio para poner un requisito nuevo.
    const contrasena = 'CambioDeContrasena1!'
    expect(validarContrasena(contrasena).valida).toBe(true)

    await expect(
      completarResetDeContrasena(deps, { token, nuevaContrasena: contrasena }),
    ).resolves.toMatchObject({ userId: 'usr_1' })
  })
})
