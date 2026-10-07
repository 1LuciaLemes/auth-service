

import { MENSAJE_CREDENCIALES_INVALIDAS } from '../../lib/errors.js'


export interface EstadoBloqueo {

  intentosFallidos: number

  bloqueadaHasta: Date | null
}


export interface PoliticaBloqueo {

  maxIntentos: number

  minutosDeBloqueo: number
}


export type DecisionBloqueo =
  | {

      permitido: true

      intentosRestantes: number
    }
  | {

      permitido: false

      hasta: Date

      minutosRestantes: number
    }


export function decidirSiPermitido(
  estado: EstadoBloqueo,
  politica: PoliticaBloqueo,
  ahora: Date,
): DecisionBloqueo {



  if (estado.bloqueadaHasta !== null && estado.bloqueadaHasta.getTime() > ahora.getTime()) {
    const minutosRestantes = Math.ceil(
      (estado.bloqueadaHasta.getTime() - ahora.getTime()) / 60_000,
    )

    return {
      permitido: false,
      hasta: estado.bloqueadaHasta,



      minutosRestantes: Math.max(1, minutosRestantes),
    }
  }




  const restantes = politica.maxIntentos - estado.intentosFallidos

  return {
    permitido: true,



    intentosRestantes: Math.max(0, restantes),
  }
}


export function registrarIntentoFallido(
  estado: EstadoBloqueo,
  politica: PoliticaBloqueo,
  ahora: Date,
): { estado: EstadoBloqueo; seBloqueo: boolean } {
  const intentos = estado.intentosFallidos + 1
  const seBloqueo = intentos >= politica.maxIntentos

  if (!seBloqueo) {
    return {
      estado: { intentosFallidos: intentos, bloqueadaHasta: null },
      seBloqueo: false,
    }
  }

  return {
    estado: {
      intentosFallidos: intentos,
      bloqueadaHasta: new Date(ahora.getTime() + politica.minutosDeBloqueo * 60_000),
    },
    seBloqueo: true,
  }
}


export function registrarIntentoExitoso(): EstadoBloqueo {
  return { intentosFallidos: 0, bloqueadaHasta: null }
}


export function mensajeDeCredencialesInvalidas(intentosRestantes: number): string {





  if (intentosRestantes === 1) {
    return 'Contrasena incorrecta. Queda 1 intento.'
  }

  if (intentosRestantes === 2) {
    return 'Contrasena incorrecta. Quedan 2 intentos.'
  }










  return MENSAJE_CREDENCIALES_INVALIDAS
}
