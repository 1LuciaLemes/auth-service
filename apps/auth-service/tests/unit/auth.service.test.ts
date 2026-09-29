/**
 * Tests del servicio de autenticacion, con repositorios falsos.
 *
 * Estos tests NO tocan Postgres: el repositorio es un objeto en memoria que
 * responde lo que cada test necesita. Es lo que compra el patron de puertos, y
 * es la razon por la que las reglas de seguridad del login se pueden testear
 * sin tener Docker andado.
 *
 * El foco esta en lo que un test de "login funciona" no reveal: que el error
 * sea el mismo para todos los fallos, que el tiempo sea el mismo, que el
 * contador de fallos se actualice, y que un email sin verificar no alcance
 * para lo importante.
 *
 * Ver explicacion.md, secciones 19, 22 y 23.
 */

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

/**
 * Estado de la base falsa, para que cada test pueda inspeccionarlo.
 *
 * OJO con `datos.usuarios` y el repositorio `usuarios`: son dos cosas
 * distintas. El primero es el Map con las filas, y el segundo es el objeto que
 * cumple el puerto. La primera version de este helper devolvia un objeto con
 * spread y paba el Map por encima con el repositorio, asi que el Map quedaba
 * inaccesible y todos los tests que lo inspeccionaban fallaban con
 * "expected undefined to be 0".
 */
interface BaseFalsa {
  /** Las filas, para poder inspeccionar y sembrar datos. */
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
  /** Estado de la cuenta. Distinto de `estado`, que es el bloqueo temporal. */
  status: EstadoCuenta
}

/** Implementa el puerto de usuarios en memoria. */
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
        // Sin esto el repositorio devuelve `undefined` y el login rechaza
        // ANTES de verificar la contrasena, que es como cinco tests de
        // bloqueo dejaron de registrar intentos sin que el error Dijera nada
        // util: el mensaje era el generico de siempre.
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
      // Se copia el evento entero, metadata incluida. Antes solo se guardaban
      // tipo y userId, y por eso los tests que comprueban que un dato sensible
      // va al audit log y NO al cliente fallaban con undefined sin que el
      // servicio tuviera nada que ver: el fake se comia el campo.
      datos.eventos.push({ ...evento })
    },
  }

  return { ...datos, usuarios, auditoria }
}

/** Agrega un usuario directo a la base falsa, saltandose el registro. */
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
      // El email se normaliza a minusculas ANTES de guardar, para que
      // Nueva@Ejemplo.com y nueva@ejemplo.com no sean dos cuentas.
      expect(emailsEnviados[0].email).toBe('nueva@ejemplo.com')
    })

    it('rechaza una contrasena debil ANTES de hashear', async () => {
      // La politica va antes del hash a proposito: argon2 cuesta ~100 ms y
      // 19 MB, y rechazar despues desperdicia justo el recurso que frena la
      // fuerza bruta.
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
        // El mensaje tiene que ser accionable: el usuario necesita saber que
        // le falta, si no esta probando contrasenas al azar.
        expect(JSON.stringify(error.metadata)).toContain('al menos')
      }
    })

    it('rechaza un email duplicado con 409', async () => {
      await registrarUsuario(deps, { email: 'dup@ejemplo.com', contrasena: CONTRASENA_VALIDA })

      // El 409 es una decision de diseno, no un descuido: el patron de
      // "exito generico" rompe la usabilidad sin evitar el ataque, porque
      // igual hay que avisarle al usuario que casi seguro ya existe.
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
      // Un email sin verificar es un campo de texto, nada mas. Nunca se usa
      // para decidir con quien se vincula una cuenta.
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

      // Si estos dos difieren, el endpoint es un enumerador de cuentas.
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

      // Decir "tu cuenta esta bloqueada" confirma que el email existe. Y
      // ademas sirve de reloj para el atacante: sabe que se acerco.
      expect(mensaje).toBe('Credenciales invalidas.')
      expect(codigo).toBe(401)
    })

    it('el mismo error para un usuario que solo se registro con Google', async () => {
      // Un usuario de Google no tiene passwordHash. Si el codigo pasara
      // `null` al verificador, el usuario recibiria un error de contrasena
      // incorrecta en vez de "entra con Google", que lo manda a una pagina
      // donde no puede hacer nada.
      agregarUsuario(base, 'google@ejemplo.com', null)

      await expect(
        iniciarSesion(deps, { email: 'google@ejemplo.com', contrasena: 'lo-que-sea' }, AHORA),
      ).rejects.toThrow('Credenciales invalidas.')
    })

    it('NO escribe el email en el audit log', async () => {
      // El audit log lo lee gente con menos permiso que la base, y un email es
      // un dato personal. Solo se guarda el motivo.
      agregarUsuario(base, 'existe@ejemplo.com', 'hash-cualquiera')

      try {
        await iniciarSesion(
          deps,
          { email: 'existe@ejemplo.com', contrasena: 'Incorrecta1!' },
          AHORA,
        )
      } catch {
        // se espera el error
      }

      const serializado = JSON.stringify(base.eventos)
      expect(serializado).not.toContain('existe@ejemplo.com')
    })
  })

  describe('login: una cuenta dada de baja no entra', () => {
    // El schema declara 'disabled' desde el principio, pero el login no lo
    // miraba. Con el bloqueo por intentos vencido (que se resuelve solo al pasar
    // la hora), una cuenta dada de baja podia iniciar sesion con normalidad.
    //
    // Todos los tests de este bloque usan un hash REAL, no 'hash-cualquiera'.
    // La comprobacion de status va DESPUES de verificar la contrasena, y
    // verificar un hash falso falla siempre: con un hash de mentira estos tests
    // se pasarian probando el camino de contrasena incorrecta, y el de 'cuenta
    // activa entra' fallaria sin que hubiera relacion con lo que prueba.
    const CONTRASENA_REAL = 'ContrasenaBuena1!'

    /** Agrega un usuario con un hash argon2 de verdad para CONTRASENA_REAL. */
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

      // Decirlo confirmaria que el email existe Y que esta dado de baja, que
      // es mas informacion que un simple "credenciales invalidas".
      expect(mensaje).toBe(MENSAJE_CREDENCIALES_INVALIDAS)
    })

    it('una contrasena CORRECTA tampoco deja entrar a una cuenta dada de baja', async () => {
      await agregarUsuarioConHashReal('u@ejemplo.com', 'disabled')

      // Este es el caso que importa. Que la contrasena sea correcta no puede
      // saltarse una baja: si el status solo se comprobara en el camino del
      // fallo, bastaria con conocer la contrasena de una cuenta deshabilitada
      // para entrar.
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
      // El status es informacion de gestion, y va al log. Nunca al cliente.
      expect(evento?.metadata?.status).toBe('disabled')
    })

    it('una cuenta activa normal entra sin problema', async () => {
      // El caso contrario, para que los tests anteriores no se puedan hacer
      // pasar rechazando siempre.
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
          // se espera el error
        }
      }

      expect(base.filas.get('u@ejemplo.com')?.estado.intentosFallidos).toBe(3)
    })

    it('NO incrementa los intentos si el email no existe', async () => {
      // Si el contador subiera tambien para emails inexistentes, el atacante
      // no ganaria nada, pero el usuario tampoco. Y el registro en la base no
      // tendria sentido para un id que no existe.
      try {
        await iniciarSesion(deps, { email: 'nadie@ejemplo.com', contrasena: 'x' }, AHORA)
      } catch {
        // se espera el error
      }

      expect(base.filas.size).toBe(0)
    })

    it('bloquea al quinto fallo', async () => {
      agregarUsuario(base, 'u@ejemplo.com', 'hash-cualquiera')

      for (let i = 0; i < 5; i++) {
        try {
          await iniciarSesion(deps, { email: 'u@ejemplo.com', contrasena: 'Incorrecta1!' }, AHORA)
        } catch {
          // se espera el error
        }
      }

      const usuario = base.filas.get('u@ejemplo.com')
      expect(usuario?.estado.bloqueadaHasta).toEqual(new Date('2026-09-29T12:15:00.000Z'))
    })

    it('resetea el contador con un login exitoso', async () => {
      // Con un hash de mentira, argon2 da false siempre, asi que "exitoso"
      // no se puede simular por esta via. Se comprueba el reset directamente
      // sobre el repositorio, que es donde vive la regla.
      const usuario = agregarUsuario(base, 'u@ejemplo.com', 'hash-cualquiera', {
        estado: { intentosFallidos: 3, bloqueadaHasta: null },
      })

      await base.usuarios.limpiarBloqueo(usuario.id)

      expect(base.filas.get('u@ejemplo.com')?.estado.intentosFallidos).toBe(0)
      expect(base.filas.get('u@ejemplo.com')?.estado.bloqueadaHasta).toBeNull()
    })

    it('el mensaje avisa cuando quedan pocos intentos', async () => {
      // Con 3 fallos previos, este es el cuarto intento y deja 1 restante: el
      // mensaje util para el usuario, que todavia puede usar "olvide mi
      // contrasena" antes de quedar afuera.
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
      // Con 4 fallos previos, este quinto intento DISPARA el bloqueo. Decir
      // "queda 1 intento" seria una mentira: la cuenta ya esta bloqueada, y
      // ademas el mensaje revelaria que la cuenta existe.
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
      // El usuario puede hacer clic dos veces o abrir el link en dos
      // pestanas. Tratarlo como exito es lo correcto; un 409 haria que la
      // segunda pestana mostrara un error confuso.
      const usuario = agregarUsuario(base, 'u@ejemplo.com', 'hash')

      await verificarEmail(deps, usuario.id, AHORA)
      await verificarEmail(deps, usuario.id, new Date('2026-09-29T13:00:00.000Z'))

      // La fecha no cambia: la primera verificacion es la que vale.
      expect(base.filas.get('u@ejemplo.com')?.emailVerifiedAt).toEqual(AHORA)
    })

    it('falla si el token apunta a un usuario que ya no existe', async () => {
      // Es un 500 disfrazado de 404: el token era valido cuando se genero, y
      // el usuario se borro despues. No es culpa de quien hace clic.
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

      // Proteger el contrato: un endpoint futuro no deberia poder exponer el
      // lockedUntil en crudo y que otro lo interprete al reves.
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
      // "login_fallido" a thousand veces puede ser un usuario que se confunde
      // de teclado. "login_fallido_usuario_inexistente" es un bot. Con un solo
      // tipo de evento no se puede construir una alerta util.
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
      // Un intento de registro con un email existente es un evento de
      // seguridad: puede ser alguien que esta armando una lista de cuentas.
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
    // Este bloque, antes, afirmaba que lo que se mandaba al email era el
    // HASH, y el test pasaba. Documentaba el bug en vez de detectarlo: con el
    // hash en el enlace, el usuario lo abre, el endpoint hashea lo que recibe y
    // busca en la base, donde esta el hash DEL HASH. Nunca coincide, y el
    // enlace no verifica nada.
    //
    // El fallo era invisible porque el registro devolvia 201 y el email salia
    // con normalidad. Nadie se enteraba hasta que alguien reportaba que su
    // enlace de verificacion no funciona.
    it('manda al email el token EN CLARO, no el hash', async () => {
      await registrarUsuario(deps, { email: 'u@ejemplo.com', contrasena: CONTRASENA_VALIDA })

      // Es lo unico que sirve: es lo que el usuario va a usar para verificar.
      expect(emailsEnviados[0].token).toBe('token-en-claro-que-va-al-email')
    })

    it('el hash NUNCA sale en el email', async () => {
      await registrarUsuario(deps, { email: 'u@ejemplo.com', contrasena: CONTRASENA_VALIDA })

      // La otra mitad de la regla: a la base va el hash, y el hash no viaja.
      // Un enlace de verificacion es publico en cuanto se reenvia o se lee en
      // un movil compartido.
      expect(emailsEnviados[0].token).not.toBe('hash-de-token-falso')
    })

    it('el token del email no es derivable del hash que se guarda', async () => {
      await registrarUsuario(deps, { email: 'u@ejemplo.com', contrasena: CONTRASENA_VALIDA })

      // Las dos mitades tienen que ser realmente distintas y no calcularse una
      // de la otra de forma reversible.
      expect(emailsEnviados[0].token).not.toContain('hash-de-token-falso')
    })
  })

  describe('carrera de dos registros con el mismo email', () => {
    it('devuelve 409, no 500, cuando el UNIQUE revienta en el INSERT', async () => {
      // Los dos registros pasan el buscarPorEmail antes de que ninguno inserte.
      // El UNIQUE de la base rechaza al segundo, y eso es un 409, no un fallo
      // del servidor.
      //
      // Con el codigo anterior, cualquier error del crear se traducía a 500.
      // El usuario reintentaba tres veces, recibia 500 las tres, y la cuenta se
      // quedaba a medias sin ninguna pista de por que.
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

      // El evento importa: un intento duplicado es informacion de seguridad
      // (puede ser alguien registrando cuentas ajenas), mientras que un 500 es
      // ruido de infraestructura.
      expect(base.eventos.some((e) => e.tipo === 'registro_rechazado_email_duplicado')).toBe(true)
    })

    it('un fallo que NO es de unicidad sigue siendo 500', async () => {
      // El riesgo de afinar la deteccion es tragarse errores de verdad. Un corte
      // de red o la base caida tienen que seguir siendo 500, porque un 409
      // diria al usuario que su email ya esta en uso, que es un diagnostico
      // falso y lo dejaria probando contrasenas al azar.
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
      // Alguns adaptadores (y algunos mocks) solo exponen `constraint`.
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
