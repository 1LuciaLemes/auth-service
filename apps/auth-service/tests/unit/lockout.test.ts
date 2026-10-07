

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


      const decision = decidirSiPermitido(
        { intentosFallidos: 4, bloqueadaHasta: null },
        POLITICA,
        AHORA,
      )

      expect(decision.permitido).toBe(true)
      if (decision.permitido) expect(decision.intentosRestantes).toBe(1)
    })

    it('nunca devuelve intentos negativos con un estado inconsistente', () => {



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


      if (decisionPosterior.permitido) expect(decisionPosterior.intentosRestantes).toBe(5)
    })
  })

  describe('el ataque de seccionamiento, que es el motivo de todo esto', () => {
    it('el rate limit por IP no frena a quien prueba muchos emails distintos', () => {








      let cuentasProbadas = 0
      const emails = Array.from({ length: 1000 }, (_, i) => `victima${i}@ejemplo.com`)

      for (const email of emails) {

        let estado: EstadoBloqueo = { intentosFallidos: 0, bloqueadaHasta: null }

        for (let intento = 0; intento < 10; intento++) {
          const decision = decidirSiPermitido(estado, POLITICA, AHORA)
          if (!decision.permitido) break




          estado = registrarIntentoFallido(estado, POLITICA, AHORA).estado
        }

        if (estado.bloqueadaHasta !== null) cuentasProbadas++
      }




      expect(cuentasProbadas).toBe(1000)
    })

    it('el contador se resetea con cada acierto, que es lo que corta el ataque', () => {







      let estado: EstadoBloqueo = { intentosFallidos: 0, bloqueadaHasta: null }

      for (let intento = 0; intento < 3; intento++) {
        const decision = decidirSiPermitido(estado, POLITICA, AHORA)
        expect(decision.permitido).toBe(true)
        estado = registrarIntentoFallido(estado, POLITICA, AHORA).estado
      }

      expect(estado.intentosFallidos).toBe(3)


      estado = registrarIntentoExitoso()

      expect(estado.intentosFallidos).toBe(0)


      const decision = decidirSiPermitido(estado, POLITICA, AHORA)
      if (decision.permitido) expect(decision.intentosRestantes).toBe(5)
    })

    it('pero SI se bloquea si el acierto llega tarde', () => {





      let estado: EstadoBloqueo = { intentosFallidos: 0, bloqueadaHasta: null }
      let seBloqueo = false

      for (let intento = 0; intento < 20; intento++) {
        const decision = decidirSiPermitido(estado, POLITICA, AHORA)
        if (!decision.permitido) {
          seBloqueo = true
          break
        }


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

      const mensaje = mensajeDeCredencialesInvalidas(5)

      expect(mensaje).toBe('Credenciales invalidas.')
      expect(mensaje.toLowerCase()).not.toContain('contrasena incorrecta')
      expect(mensaje.toLowerCase()).not.toContain('no existe')
    })

    it('avisa cuando quedan pocos intentos', () => {


      expect(mensajeDeCredencialesInvalidas(2)).toContain('Quedan 2 intentos')
      expect(mensajeDeCredencialesInvalidas(1)).toContain('Queda 1 intento')
    })

    it('usa singular en "queda 1 intento"', () => {



      expect(mensajeDeCredencialesInvalidas(1)).not.toContain('Quedan 1')
    })
  })
})
