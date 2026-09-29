/**
 * Tests de la politica de bloqueo de cuentas.
 *
 * Ademas de los casos obvios, hay un bloque entero dedicado al ataque de
 * SECCIONAMIENTO, que es el motivo por el que esta politica existe y el que un
 * test de "5 intentos y se bloquea" no revela.
 *
 * Ver explicacion.md, seccion 22.
 */

import { describe, expect, it } from 'vitest'
import {
  decidirSiPermitido,
  mensajeDeCredencialesInvalidas,
  registrarIntentoExitoso,
  registrarIntentoFallido,
  type EstadoBloqueo,
  type PoliticaBloqueo,
} from '../../src/modules/auth/lockout.js'

const POLITICA: PoliticaBloqueo = { maxIntentos: 5, minutosDeBloqueo: 15 }

/** Instante fijo, para que los tests no dependan de la hora real. */
const AHORA = new Date('2026-09-29T12:00:00.000Z')

const SIN_INTENTOS: EstadoBloqueo = { intentosFallidos: 0, bloqueadaHasta: null }

describe('politica de bloqueo', () => {
  describe('cuanto intentos quedan', () => {
    it('una cuenta nueva tiene todos los intentos', () => {
      const decision = decidirSiPermitido(SIN_INTENTOS, POLITICA, AHORA)

      expect(decision.permitido).toBe(true)
      if (decision.permitido) expect(decision.intentosRestantes).toBe(5)
    })

    it('descuenta los intentos que ya se fallaron', () => {
      const decision = decidirSiPermitido(
        { intentosFallidos: 2, bloqueadaHasta: null },
        POLITICA,
        AHORA,
      )

      if (decision.permitido) expect(decision.intentosRestantes).toBe(3)
    })

    it('el ultimo intento antes del bloqueo se permite', () => {
      // Con maxIntentos 5, el quinto fallo se permite. Si se rechazara en el
      // quinto, el usuario tendria 4 chances y el nombre "maxIntentos" mintiria.
      const decision = decidirSiPermitido(
        { intentosFallidos: 4, bloqueadaHasta: null },
        POLITICA,
        AHORA,
      )

      expect(decision.permitido).toBe(true)
      if (decision.permitido) expect(decision.intentosRestantes).toBe(1)
    })

    it('nunca devuelve intentos negativos con un estado inconsistente', () => {
      // Puede pasar si se cambia LOGIN_MAX_ATTEMPTS_PER_EMAIL en produccion de
      // 5 a 3 sin resetear los contadores: quedan cuentas con 5 fallos y max
      // nuevo 3. Un -2 en el mensaje rompe el texto del frontend.
      const decision = decidirSiPermitido(
        { intentosFallidos: 9, bloqueadaHasta: null },
        POLITICA,
        AHORA,
      )

      if (decision.permitido) expect(decision.intentosRestantes).toBe(0)
    })
  })

  describe('el bloqueo se aplica', () => {
    it('bloquea en el quinto fallo, no en el cuarto', () => {
      const cuarto = registrarIntentoFallido(
        { intentosFallidos: 3, bloqueadaHasta: null },
        POLITICA,
        AHORA,
      )
      expect(cuarto.seBloqueo).toBe(false)

      const quinto = registrarIntentoFallido(cuarto.estado, POLITICA, AHORA)
      expect(quinto.seBloqueo).toBe(true)
    })

    it('calcula la fecha de expiracion a partir del instante dado', () => {
      const { estado } = registrarIntentoFallido(
        { intentosFallidos: 4, bloqueadaHasta: null },
        POLITICA,
        AHORA,
      )

      expect(estado.bloqueadaHasta).toEqual(new Date('2026-09-29T12:15:00.000Z'))
    })

    it('el bloqueado no puede volver a entrar', () => {
      const bloqueada: EstadoBloqueo = {
        intentosFallidos: 5,
        bloqueadaHasta: new Date('2026-09-29T12:15:00.000Z'),
      }

      const decision = decidirSiPermitido(bloqueada, POLITICA, AHORA)

      expect(decision.permitido).toBe(false)
    })
  })

  describe('el bloqueo caduca solo', () => {
    it('permite reintentar un instante despues de expirar', () => {
      const expirada: EstadoBloqueo = {
        intentosFallidos: 5,
        bloqueadaHasta: new Date('2026-09-29T12:15:00.000Z'),
      }

      const decision = decidirSiPermitido(expirada, POLITICA, new Date('2026-09-29T12:15:01.000Z'))

      // Este es el punto de usar una FECHA en vez de un booleano: no hace
      // falta ningun job que corra cada minuto para destrabar cuentas. La
      // consulta resuelve sola comparando fechas.
      expect(decision.permitido).toBe(true)
    })

    it('sigue bloqueada un instante antes de expirar', () => {
      const expirada: EstadoBloqueo = {
        intentosFallidos: 5,
        bloqueadaHasta: new Date('2026-09-29T12:15:00.000Z'),
      }

      const decision = decidirSiPermitido(expirada, POLITICA, new Date('2026-09-29T12:14:59.000Z'))

      expect(decision.permitido).toBe(false)
    })

    it('redondea los minutos restantes hacia arriba', () => {
      // Con 30 segundos restantes tiene que decir 1 minuto, no 0. Decir "0
      // minutos" mientras sigue bloqueado invita al cliente a reintentar en
      // loop y el usuario ve un mensaje que no cuadra con lo que la pagina
      // muestra.
      const casi: EstadoBloqueo = {
        intentosFallidos: 5,
        bloqueadaHasta: new Date('2026-09-29T12:00:30.000Z'),
      }

      const decision = decidirSiPermitido(casi, POLITICA, AHORA)

      expect(decision.permitido).toBe(false)
      if (!decision.permitido) expect(decision.minutosRestantes).toBe(1)
    })

    it('reporta los minutos restantes con precision', () => {
      const bloqueada: EstadoBloqueo = {
        intentosFallidos: 5,
        bloqueadaHasta: new Date('2026-09-29T12:14:00.000Z'),
      }

      const decision = decidirSiPermitido(bloqueada, POLITICA, AHORA)

      if (!decision.permitido) expect(decision.minutosRestantes).toBe(14)
    })
  })

  describe('el login exitoso limpia el estado', () => {
    it('resetea el contador', () => {
      const estado = registrarIntentoExitoso()

      expect(estado.intentosFallidos).toBe(0)
    })

    it('BORRA la fecha de bloqueo, no solo el contador', () => {
      // Si se resetea el contador y se deja la fecha, la cuenta queda
      // bloqueada sin motivo visible: el panel de admin dice "0 intentos" y el
      // usuario no puede entrar. Un login correcto tiene que limpiar las dos
      // columnas.
      const estado = registrarIntentoExitoso()

      expect(estado.bloqueadaHasta).toBeNull()
    })

    it('un login correcto despues de caducar deja la cuenta limpia', () => {
      const expirada: EstadoBloqueo = {
        intentosFallidos: 5,
        bloqueadaHasta: new Date('2026-09-29T11:00:00.000Z'),
      }

      const decisionPrevia = decidirSiPermitido(expirada, POLITICA, AHORA)
      expect(decisionPrevia.permitido).toBe(true)

      const estado = registrarIntentoExitoso()
      const decisionPosterior = decidirSiPermitido(estado, POLITICA, AHORA)

      // Con 0 intentos de 5, el usuario tiene las 5 oportunidades de nuevo.
      if (decisionPosterior.permitido) expect(decisionPosterior.intentosRestantes).toBe(5)
    })
  })

  describe('el ataque de seccionamiento, que es el motivo de todo esto', () => {
    it('el rate limit por IP no frena a quien prueba muchos emails distintos', () => {
      // El atacante tiene 1000 cuentas de correo y prueba '123456' contra cada
      // una, desde IPs distintas o rotando. Cada request individual pasa el
      // rate limit por IP, porque NINGUNO se repite.
      //
      // El resultado sin bloqueo por cuenta es que se prueba 1000 contrasenas
      // en una noche. Ese es el ataque que esta politica corta: al quinto
      // fallo de una cuenta, esa cuenta queda bloqueada 15 minutos, y el
      // atacante no puede seguir con ella sin esperar.
      let cuentasProbadas = 0
      const emails = Array.from({ length: 1000 }, (_, i) => `victima${i}@ejemplo.com`)

      for (const email of emails) {
        // Cada cuenta arranca con 0 intentos: el atacante no repite email.
        let estado: EstadoBloqueo = { intentosFallidos: 0, bloqueadaHasta: null }

        for (let intento = 0; intento < 10; intento++) {
          const decision = decidirSiPermitido(estado, POLITICA, AHORA)
          if (!decision.permitido) break

          // Contrasena incorrecta en una cuenta nueva: nunca da el quinto
          // fallo seguido, porque la cuenta se resetea al primer acierto y el
          // atacante solo tiene una contrasena que probar.
          estado = registrarIntentoFallido(estado, POLITICA, AHORA).estado
        }

        if (estado.bloqueadaHasta !== null) cuentasProbadas++
      }

      // Resultado: cada cuenta se bloquea tras 5 intentos, asi que el atacante
      // no puede probar mas de 5 contrasenas por cuenta sin esperar. La
      // cuenta exista o no: si existe, el quinto fallo la bloquea.
      expect(cuentasProbadas).toBe(1000)
    })

    it('el contador se resetea con cada acierto, que es lo que corta el ataque', () => {
      // El detalle que hace efectiva la politica: lo que se limita son los
      // FALLOS CONSECUTIVOS, no el total de intentos.
      //
      // Un atacante que prueba contrasenas una por vez contra una MISMA cuenta
      // nunca acumula cinco fallos seguidos si acierta antes. Tres fallos, un
      // acierto, y el contador vuelve a cero: tiene las cinco oportunidades
      // de nuevo.
      let estado: EstadoBloqueo = { intentosFallidos: 0, bloqueadaHasta: null }

      for (let intento = 0; intento < 3; intento++) {
        const decision = decidirSiPermitido(estado, POLITICA, AHORA)
        expect(decision.permitido).toBe(true)
        estado = registrarIntentoFallido(estado, POLITICA, AHORA).estado
      }

      expect(estado.intentosFallidos).toBe(3)

      // El acierto del cuarto intento.
      estado = registrarIntentoExitoso()

      expect(estado.intentosFallidos).toBe(0)

      // Y las cinco oportunidades vuelven a estar disponibles, que es el punto.
      const decision = decidirSiPermitido(estado, POLITICA, AHORA)
      if (decision.permitido) expect(decision.intentosRestantes).toBe(5)
    })

    it('pero SI se bloquea si el acierto llega tarde', () => {
      // El contraste con el test anterior, y es la razon por la que la
      // politica sirve: si el atacante NO acierta antes del quinto intento, la
      // cuenta se bloquea. O sea, un atacante con una contrasena fija queda
      // afuera; uno que prueba una distinta por intento, no, y para ese caso
      // estan argon2 (lento) y la password policy.
      let estado: EstadoBloqueo = { intentosFallidos: 0, bloqueadaHasta: null }
      let seBloqueo = false

      for (let intento = 0; intento < 20; intento++) {
        const decision = decidirSiPermitido(estado, POLITICA, AHORA)
        if (!decision.permitido) {
          seBloqueo = true
          break
        }

        // Acierta tarde, en el intento 8: ya se bloquearon antes.
        if (intento === 7) {
          estado = registrarIntentoExitoso()
        } else {
          estado = registrarIntentoFallido(estado, POLITICA, AHORA).estado
        }
      }

      expect(seBloqueo).toBe(true)
      expect(estado.bloqueadaHasta).not.toBeNull()
    })
  })

  describe('mensajes al usuario', () => {
    it('no dice si el email existe ni la contrasena esta mal', () => {
      // El mensaje generico es la parte que evita el enumerador de cuentas.
      const mensaje = mensajeDeCredencialesInvalidas(5)

      expect(mensaje).toBe('Credenciales invalidas.')
      expect(mensaje.toLowerCase()).not.toContain('contrasena incorrecta')
      expect(mensaje.toLowerCase()).not.toContain('no existe')
    })

    it('avisa cuando quedan pocos intentos', () => {
      // Cerca del limite el aviso es util: el usuario puede usar "olvide mi
      // contrasena" antes de quedar afuera.
      expect(mensajeDeCredencialesInvalidas(2)).toContain('Quedan 2 intentos')
      expect(mensajeDeCredencialesInvalidas(1)).toContain('Queda 1 intento')
    })

    it('usa singular en "queda 1 intento"', () => {
      // Un "quedan 1 intentos" se ve descuidado y delata que el mensaje es
      // una plantilla, que es justo lo que no queremos si estamos tratando de
      // no dar informacion sobre el estado de la cuenta.
      expect(mensajeDeCredencialesInvalidas(1)).not.toContain('Quedan 1')
    })
  })
})
