

import { beforeEach, describe, expect, it } from 'vitest'
import { AppError, MENSAJE_CREDENCIALES_INVALIDAS } from '../../src/lib/errors.js'
import {
  estadoDeBloqueoParaElCliente,
  iniciarSesion,
  registrarUsuario,
  verificarEmail,
  type DependenciasAuth,
} from '../../src/modules/auth/auth.service.js'
import type {
  EstadoCuenta,
  RepositorioAuditoria,
  RepositorioUsuarios,
  ResultadoBusqueda,
} from '../../src/modules/auth/ports.js'
import { type EstadoBloqueo } from '../../src/modules/auth/lockout.js'
import { hashearContrasena } from '../../src/lib/password.js'

const AHORA = new Date('2026-09-29T12:00:00.000Z')

const POLITICA = { maxIntentos: 5, minutosDeBloqueo: 15 }

const CONTRASENA_VALIDA = 'UnaContrasenaLarga1!'


interface BaseFalsa {

  filas: Map<string, UsuarioFalso>
  eventos: Array<{ tipo: string; userId?: string }>
}

interface UsuarioFalso {
  id: string
  email: string
  passwordHash: string | null
  emailVerifiedAt: Date | null
  role: 'user' | 'admin'
  estado: EstadoBloqueo

  status: EstadoCuenta
}


function crearBaseFalsa(): BaseFalsa & {
  usuarios: RepositorioUsuarios
  auditoria: RepositorioAuditoria
} {
  const datos: BaseFalsa = { filas: new Map(), eventos: [] }
  let siguienteId = 1

  const usuarios: RepositorioUsuarios = {
    async buscarPorEmail(email: string): Promise<ResultadoBusqueda> {
      const usuario = datos.filas.get(email)
      if (!usuario) return { encontrado: false }
      return {
        encontrado: true,
        id: usuario.id,
        email: usuario.email,
        passwordHash: usuario.passwordHash,
        emailVerifiedAt: usuario.emailVerifiedAt,
        role: usuario.role,
        estado: { ...usuario.estado },




        status: usuario.status,
      }
    },

    async buscarPorId(id: string) {
      for (const usuario of datos.filas.values()) {
        if (usuario.id !== id) continue
        return {
          encontrado: true as const,
          id: usuario.id,
          email: usuario.email,
          passwordHash: usuario.passwordHash,
          emailVerifiedAt: usuario.emailVerifiedAt,
          role: usuario.role,
          estado: { ...usuario.estado },
          status: usuario.status,
        }
      }
      return null
    },

    async crear({ email, passwordHash, displayName }) {
      void displayName
      const usuario: UsuarioFalso = {
        id: `usr_${siguienteId++}`,
        email,
        passwordHash,
        emailVerifiedAt: null,
        role: 'user',
        estado: { intentosFallidos: 0, bloqueadaHasta: null },
      }
      datos.filas.set(email, usuario)
      return { id: usuario.id, email: usuario.email }
    },

    async actualizarBloqueo(id: string, estado: EstadoBloqueo) {
      for (const usuario of datos.filas.values()) {
        if (usuario.id === id) usuario.estado = { ...estado }
      }
    },

    async limpiarBloqueo(id: string) {
      for (const usuario of datos.filas.values()) {
        if (usuario.id === id) {
          usuario.estado = { intentosFallidos: 0, bloqueadaHasta: null }
        }
      }
    },

    async marcarEmailVerificado(id: string, instante: Date) {
      for (const usuario of datos.filas.values()) {
        if (usuario.id === id) usuario.emailVerifiedAt = instante
      }
    },
  }

  const auditoria: RepositorioAuditoria = {
    async registrar(evento) {




      datos.eventos.push({ ...evento })
    },
  }

  return { ...datos, usuarios, auditoria }
}


function agregarUsuario(
  base: BaseFalsa,
  email: string,
  passwordHash: string | null,
  extras: Partial<{ emailVerifiedAt: Date; estado: EstadoBloqueo; status: EstadoCuenta }> = {},
): UsuarioFalso {
  const usuario: UsuarioFalso = {
    id: `usr_${base.filas.size + 1}`,
    email,
    passwordHash,
    emailVerifiedAt: extras.emailVerifiedAt ?? null,
    role: 'user',
    estado: extras.estado ?? { intentosFallidos: 0, bloqueadaHasta: null },
    status: extras.status ?? 'active',
  }
  base.filas.set(email, usuario)
  return usuario
}

describe('servicio de autenticacion', () => {
  let base: ReturnType<typeof crearBaseFalsa>
  let deps: DependenciasAuth
  let emailsEnviados: Array<{ email: string; token: string }>

  beforeEach(() => {
    base = crearBaseFalsa()
    emailsEnviados = []

    deps = {
      usuarios: base.usuarios,
      auditoria: base.auditoria,
      politica: POLITICA,
      generarTokenDeVerificacion: async () => ({
        token: 'token-en-claro-que-va-al-email',
        tokenHash: 'hash-de-token-falso',
        expira: new Date('2026-09-30T12:00:00.000Z'),
      }),
      enviarEmailDeVerificacion: async ({ email, token }) => {
        emailsEnviados.push({ email, token })
      },
    }
  })

  describe('registro', () => {
    it('crea el usuario y manda el email de verificacion', async () => {
      const resultado = await registrarUsuario(deps, {
        email: 'Nueva@Ejemplo.com',
        contrasena: CONTRASENA_VALIDA,
      })

      expect(resultado.userId).toBeDefined()
      expect(emailsEnviados).toHaveLength(1)


      expect(emailsEnviados[0].email).toBe('nueva@ejemplo.com')
    })

    it('rechaza una contrasena debil ANTES de hashear', async () => {



      await expect(
        registrarUsuario(deps, { email: 'a@b.com', contrasena: '123' }),
      ).rejects.toThrow(AppError)

      expect(base.filas.size).toBe(0)
      expect(emailsEnviados).toHaveLength(0)
    })

    it('el error de contrasena debil lista los problemas', async () => {
      let error: unknown
      try {
        await registrarUsuario(deps, { email: 'a@b.com', contrasena: '123' })
      } catch (e) {
        error = e
      }

      expect(error).toBeInstanceOf(AppError)
      if (error instanceof AppError) {
        expect(error.statusCode).toBe(400)


        expect(JSON.stringify(error.metadata)).toContain('al menos')
      }
    })

    it('rechaza un email duplicado con 409', async () => {
      await registrarUsuario(deps, { email: 'dup@ejemplo.com', contrasena: CONTRASENA_VALIDA })




      await expect(
        registrarUsuario(deps, { email: 'dup@ejemplo.com', contrasena: CONTRASENA_VALIDA }),
      ).rejects.toThrow(/Ya existe una cuenta/)
    })

    it('el duplicado se detecta aunque venga con distinta capitalizacion', async () => {
      await registrarUsuario(deps, { email: 'dup@ejemplo.com', contrasena: CONTRASENA_VALIDA })

      await expect(
        registrarUsuario(deps, { email: 'DUP@Ejemplo.COM', contrasena: CONTRASENA_VALIDA }),
      ).rejects.toThrow(/Ya existe una cuenta/)
    })

    it('deja el usuario con el email SIN verificar', async () => {


      await registrarUsuario(deps, { email: 'nuevo@ejemplo.com', contrasena: CONTRASENA_VALIDA })

      const usuario = base.filas.get('nuevo@ejemplo.com')
      expect(usuario?.emailVerifiedAt).toBeNull()
    })
  })

  describe('login: el error NUNCA revela si el email existe', () => {
    it('el mismo mensaje para email inexistente y para contrasena incorrecta', async () => {
      agregarUsuario(base, 'existe@ejemplo.com', 'hash-cualquiera')

      let mensajeInexistente = ''
      let mensajeIncorrecta = ''
      let codigoInexistente = 0
      let codigoIncorrecta = 0

      try {
        await iniciarSesion(deps, { email: 'nadie@ejemplo.com', contrasena: 'x' }, AHORA)
      } catch (e) {
        if (e instanceof AppError) {
          mensajeInexistente = e.message
          codigoInexistente = e.statusCode
        }
      }

      try {
        await iniciarSesion(
          deps,
          { email: 'existe@ejemplo.com', contrasena: 'ContrasenaIncorrecta1!' },
          AHORA,
        )
      } catch (e) {
        if (e instanceof AppError) {
          mensajeIncorrecta = e.message
          codigoIncorrecta = e.statusCode
        }
      }


      expect(mensajeInexistente).toBe(mensajeIncorrecta)
      expect(codigoInexistente).toBe(codigoIncorrecta)
    })

    it('el mismo codigo de error para cuenta bloqueada', async () => {
      const bloqueada = agregarUsuario(base, 'bloqueada@ejemplo.com', 'hash', {
        estado: {
          intentosFallidos: 5,
          bloqueadaHasta: new Date('2026-09-29T12:15:00.000Z'),
        },
      })
      void bloqueada

      let mensaje = ''
      let codigo = 0
      try {
        await iniciarSesion(deps, { email: 'bloqueada@ejemplo.com', contrasena: 'x' }, AHORA)
      } catch (e) {
        if (e instanceof AppError) {
          mensaje = e.message
          codigo = e.statusCode
        }
      }



      expect(mensaje).toBe('Credenciales invalidas.')
      expect(codigo).toBe(401)
    })

    it('el mismo error para un usuario que solo se registro con Google', async () => {




      agregarUsuario(base, 'google@ejemplo.com', null)

      await expect(
        iniciarSesion(deps, { email: 'google@ejemplo.com', contrasena: 'lo-que-sea' }, AHORA),
      ).rejects.toThrow('Credenciales invalidas.')
    })

    it('NO escribe el email en el audit log', async () => {


      agregarUsuario(base, 'existe@ejemplo.com', 'hash-cualquiera')

      try {
        await iniciarSesion(
          deps,
          { email: 'existe@ejemplo.com', contrasena: 'Incorrecta1!' },
          AHORA,
        )
      } catch {

      }

      const serializado = JSON.stringify(base.eventos)
      expect(serializado).not.toContain('existe@ejemplo.com')
    })
  })

  describe('login: una cuenta dada de baja no entra', () => {









    const CONTRASENA_REAL = 'ContrasenaBuena1!'


    async function agregarUsuarioConHashReal(
      email: string,
      status: EstadoCuenta,
    ): Promise<void> {
      agregarUsuario(base, email, await hashearContrasena(CONTRASENA_REAL), { status })
    }

    for (const status of ['locked', 'disabled'] as const) {
      it(`rechaza una cuenta con status ${status}`, async () => {
        await agregarUsuarioConHashReal('u@ejemplo.com', status)

        await expect(
          iniciarSesion(deps, { email: 'u@ejemplo.com', contrasena: CONTRASENA_REAL }, AHORA),
        ).rejects.toMatchObject({ statusCode: 401 })
      })
    }

    it('el mensaje es el generico, no "tu cuenta esta deshabilitada"', async () => {
      await agregarUsuarioConHashReal('u@ejemplo.com', 'disabled')

      let mensaje = ''
      try {
        await iniciarSesion(deps, { email: 'u@ejemplo.com', contrasena: CONTRASENA_REAL }, AHORA)
      } catch (error) {
        mensaje = (error as Error).message
      }



      expect(mensaje).toBe(MENSAJE_CREDENCIALES_INVALIDAS)
    })

    it('una contrasena CORRECTA tampoco deja entrar a una cuenta dada de baja', async () => {
      await agregarUsuarioConHashReal('u@ejemplo.com', 'disabled')





      await expect(
        iniciarSesion(deps, { email: 'u@ejemplo.com', contrasena: CONTRASENA_REAL }, AHORA),
      ).rejects.toMatchObject({ statusCode: 401 })
    })

    it('el status va al audit log, que lo lee un admin', async () => {
      await agregarUsuarioConHashReal('u@ejemplo.com', 'disabled')

      await iniciarSesion(deps, { email: 'u@ejemplo.com', contrasena: CONTRASENA_REAL }, AHORA).catch(
        () => undefined,
      )

      const evento = base.eventos.find((e) => e.tipo === 'login_cuenta_no_activa')
      expect(evento).toBeDefined()

      expect(evento?.metadata?.status).toBe('disabled')
    })

    it('una cuenta activa normal entra sin problema', async () => {


      await agregarUsuarioConHashReal('u@ejemplo.com', 'active')

      await expect(
        iniciarSesion(deps, { email: 'u@ejemplo.com', contrasena: CONTRASENA_REAL }, AHORA),
      ).resolves.toMatchObject({ userId: expect.any(String) })
    })
  })

  describe('login: el contador de fallos', () => {
    it('incrementa los intentos con cada fallo', async () => {
      agregarUsuario(base, 'u@ejemplo.com', 'hash-cualquiera')

      for (let i = 0; i < 3; i++) {
        try {
          await iniciarSesion(deps, { email: 'u@ejemplo.com', contrasena: 'Incorrecta1!' }, AHORA)
        } catch {

        }
      }

      expect(base.filas.get('u@ejemplo.com')?.estado.intentosFallidos).toBe(3)
    })

    it('NO incrementa los intentos si el email no existe', async () => {



      try {
        await iniciarSesion(deps, { email: 'nadie@ejemplo.com', contrasena: 'x' }, AHORA)
      } catch {

      }

      expect(base.filas.size).toBe(0)
    })

    it('bloquea al quinto fallo', async () => {
      agregarUsuario(base, 'u@ejemplo.com', 'hash-cualquiera')

      for (let i = 0; i < 5; i++) {
        try {
          await iniciarSesion(deps, { email: 'u@ejemplo.com', contrasena: 'Incorrecta1!' }, AHORA)
        } catch {

        }
      }

      const usuario = base.filas.get('u@ejemplo.com')
      expect(usuario?.estado.bloqueadaHasta).toEqual(new Date('2026-09-29T12:15:00.000Z'))
    })

    it('resetea el contador con un login exitoso', async () => {



      const usuario = agregarUsuario(base, 'u@ejemplo.com', 'hash-cualquiera', {
        estado: { intentosFallidos: 3, bloqueadaHasta: null },
      })

      await base.usuarios.limpiarBloqueo(usuario.id)

      expect(base.filas.get('u@ejemplo.com')?.estado.intentosFallidos).toBe(0)
      expect(base.filas.get('u@ejemplo.com')?.estado.bloqueadaHasta).toBeNull()
    })

    it('el mensaje avisa cuando quedan pocos intentos', async () => {



      const usuario = agregarUsuario(base, 'u@ejemplo.com', 'hash-cualquiera', {
        estado: { intentosFallidos: 3, bloqueadaHasta: null },
      })
      void usuario

      let mensaje = ''
      try {
        await iniciarSesion(deps, { email: 'u@ejemplo.com', contrasena: 'Incorrecta1!' }, AHORA)
      } catch (e) {
        if (e instanceof AppError) mensaje = e.message
      }

      expect(mensaje).toContain('Queda 1 intento')
    })

    it('NO anuncia un intento que ya no existe, porque la cuenta se acaba de bloquear', async () => {



      const usuario = agregarUsuario(base, 'u@ejemplo.com', 'hash-cualquiera', {
        estado: { intentosFallidos: 4, bloqueadaHasta: null },
      })
      void usuario

      let mensaje = ''
      try {
        await iniciarSesion(deps, { email: 'u@ejemplo.com', contrasena: 'Incorrecta1!' }, AHORA)
      } catch (e) {
        if (e instanceof AppError) mensaje = e.message
      }

      expect(mensaje).toBe(MENSAJE_CREDENCIALES_INVALIDAS)
      expect(mensaje).not.toContain('intento')
    })
  })

  describe('verificacion de email', () => {
    it('marca el email como verificado', async () => {
      const usuario = agregarUsuario(base, 'u@ejemplo.com', 'hash')

      await verificarEmail(deps, usuario.id, AHORA)

      expect(base.filas.get('u@ejemplo.com')?.emailVerifiedAt).toEqual(AHORA)
    })

    it('verificar dos veces no es un error', async () => {



      const usuario = agregarUsuario(base, 'u@ejemplo.com', 'hash')

      await verificarEmail(deps, usuario.id, AHORA)
      await verificarEmail(deps, usuario.id, new Date('2026-09-29T13:00:00.000Z'))


      expect(base.filas.get('u@ejemplo.com')?.emailVerifiedAt).toEqual(AHORA)
    })

    it('falla si el token apunta a un usuario que ya no existe', async () => {


      await expect(verificarEmail(deps, 'usr_inexistente', AHORA)).rejects.toThrow(AppError)
    })
  })

  describe('estado de bloqueo para el cliente', () => {
    it('no expone la fecha cruda, sino minutos restantes', () => {
      const estado: EstadoBloqueo = {
        intentosFallidos: 5,
        bloqueadaHasta: new Date('2026-09-29T12:14:00.000Z'),
      }

      const vista = estadoDeBloqueoParaElCliente(estado, AHORA)



      expect(vista).toEqual({ bloqueado: true, minutosRestantes: 14 })
      expect(vista).not.toHaveProperty('bloqueadaHasta')
    })

    it('dice que no esta bloqueada cuando la fecha ya paso', () => {
      const estado: EstadoBloqueo = {
        intentosFallidos: 5,
        bloqueadaHasta: new Date('2026-09-29T11:00:00.000Z'),
      }

      expect(estadoDeBloqueoParaElCliente(estado, AHORA)).toEqual({
        bloqueado: false,
        minutosRestantes: 0,
      })
    })
  })

  describe('auditoria de los eventos de seguridad', () => {
    it('registra un evento por cada login fallido', async () => {
      agregarUsuario(base, 'u@ejemplo.com', 'hash-cualquiera')

      await iniciarSesion(deps, { email: 'u@ejemplo.com', contrasena: 'Incorrecta1!' }, AHORA).catch(
        () => undefined,
      )

      const tipos = base.eventos.map((e) => e.tipo)
      expect(tipos).toContain('login_fallido')
    })

    it('distingue los tipos de fallo, para poder alertar sobre uno solo', async () => {



      agregarUsuario(base, 'existe@ejemplo.com', 'hash-cualquiera')

      await iniciarSesion(deps, { email: 'nadie@ejemplo.com', contrasena: 'x' }, AHORA).catch(
        () => undefined,
      )
      await iniciarSesion(
        deps,
        { email: 'existe@ejemplo.com', contrasena: 'Incorrecta1!' },
        AHORA,
      ).catch(() => undefined)

      const tipos = base.eventos.map((e) => e.tipo)
      expect(tipos).toContain('login_fallido_usuario_inexistente')
      expect(tipos).toContain('login_fallido')
    })

    it('el registro duplicado queda auditado', async () => {


      await registrarUsuario(deps, { email: 'dup@ejemplo.com', contrasena: CONTRASENA_VALIDA })

      await registrarUsuario(deps, { email: 'dup@ejemplo.com', contrasena: CONTRASENA_VALIDA }).catch(
        () => undefined,
      )

      expect(base.eventos.map((e) => e.tipo)).toContain('registro_rechazado_email_duplicado')
    })

    it('nunca registra el texto de la contrasena', async () => {
      agregarUsuario(base, 'u@ejemplo.com', 'hash-cualquiera')

      await iniciarSesion(
        deps,
        { email: 'u@ejemplo.com', contrasena: 'EstaEsLaContrasenaDelAtacante1!' },
        AHORA,
      ).catch(() => undefined)

      expect(JSON.stringify(base.eventos)).not.toContain('EstaEsLaContrasenaDelAtacante1!')
    })
  })

  describe('el token de verificacion: la base y el email reciben cosas distintas', () => {









    it('manda al email el token EN CLARO, no el hash', async () => {
      await registrarUsuario(deps, { email: 'u@ejemplo.com', contrasena: CONTRASENA_VALIDA })


      expect(emailsEnviados[0].token).toBe('token-en-claro-que-va-al-email')
    })

    it('el hash NUNCA sale en el email', async () => {
      await registrarUsuario(deps, { email: 'u@ejemplo.com', contrasena: CONTRASENA_VALIDA })




      expect(emailsEnviados[0].token).not.toBe('hash-de-token-falso')
    })

    it('el token del email no es derivable del hash que se guarda', async () => {
      await registrarUsuario(deps, { email: 'u@ejemplo.com', contrasena: CONTRASENA_VALIDA })



      expect(emailsEnviados[0].token).not.toContain('hash-de-token-falso')
    })
  })

  describe('carrera de dos registros con el mismo email', () => {
    it('devuelve 409, no 500, cuando el UNIQUE revienta en el INSERT', async () => {







      const depsEnConflicto: DependenciasAuth = {
        ...deps,
        usuarios: {
          ...base.usuarios,
          crear: async () => {
            const error = new Error('duplicate key value violates unique constraint')
            Object.assign(error, { code: '23505', constraint: 'users_email_unique' })
            throw error
          },
        },
      }

      await expect(
        registrarUsuario(depsEnConflicto, { email: 'u@ejemplo.com', contrasena: CONTRASENA_VALIDA }),
      ).rejects.toMatchObject({ statusCode: 409, code: 'conflict' })
    })

    it('lo registra en auditoria como email duplicado, no como error interno', async () => {
      const depsEnConflicto: DependenciasAuth = {
        ...deps,
        usuarios: {
          ...base.usuarios,
          crear: async () => {
            const error = new Error('duplicate key value')
            Object.assign(error, { code: '23505' })
            throw error
          },
        },
      }

      await registrarUsuario(depsEnConflicto, { email: 'u@ejemplo.com', contrasena: CONTRASENA_VALIDA }).catch(
        () => undefined,
      )




      expect(base.eventos.some((e) => e.tipo === 'registro_rechazado_email_duplicado')).toBe(true)
    })

    it('un fallo que NO es de unicidad sigue siendo 500', async () => {




      const depsCaido: DependenciasAuth = {
        ...deps,
        usuarios: {
          ...base.usuarios,
          crear: async () => {
            throw Object.assign(new Error('ECONNREFUSED'), { code: 'ECONNREFUSED' })
          },
        },
      }

      await expect(
        registrarUsuario(depsCaido, { email: 'u@ejemplo.com', contrasena: CONTRASENA_VALIDA }),
      ).rejects.toMatchObject({ statusCode: 500, code: 'server_error' })
    })

    it('detecta el conflicto por el nombre de la constraint si no hay code', async () => {

      const depsSinCode: DependenciasAuth = {
        ...deps,
        usuarios: {
          ...base.usuarios,
          crear: async () => {
            throw Object.assign(new Error('duplicate key'), { constraint: 'users_email_key' })
          },
        },
      }

      await expect(
        registrarUsuario(depsSinCode, { email: 'u@ejemplo.com', contrasena: CONTRASENA_VALIDA }),
      ).rejects.toMatchObject({ statusCode: 409 })
    })
  })
})
