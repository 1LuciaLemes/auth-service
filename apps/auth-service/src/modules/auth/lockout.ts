/**
 * Politica de bloqueo de cuentas por intentos fallidos.
 *
 * Es el modulo que decide si una cuenta se bloquea, por cuanto tiempo, y si se
 * puede volver a intentar. Logica pura: recibe el estado, devuelve el estado.
 * Sin base de datos, sin reloj, sin nada. Por eso se puede testear cada
 * combinacion de borde en milisegundos, que es lo que necesita un archivo que
 * decide si le cierran la puerta a un usuario.
 *
 * QUE PROBLEMA RESUELVE Y POR QUE NO BASTA EL RATE LIMIT
 *
 * El rate limit por IP frena a un bot que prueba contrasenas desde una sola
 * maquina. No frena a un atacante con mil cuentas de correo, que prueba una
 * contrasena contra cada email desde IPs distintas. Cada request individual
 * pasa el rate limit, y entre todas seccionan la tabla entera.
 *
 * Por eso el rate limit NO es lo mismo que el bloqueo, y por eso el schema
 * tiene las dos cosas:
 *
 *   rate limit  = requests por IP, en Redis, evita el flood
 *   bloqueo     = fallos de autenticacion por CUENTA, en la fila del usuario,
 *                 evita el seccionamiento de la tabla
 *
 * Ver explicacion.md, seccion 22.
 */

import { MENSAJE_CREDENCIALES_INVALIDAS } from '../../lib/errors.js'

/** Estado de una cuenta en lo que respecta al bloqueo. */
export interface EstadoBloqueo {
  /** Fallos consecutivos. Se resetea a 0 con cada login exitoso. */
  intentosFallidos: number
  /** Instante de expiracion del bloqueo, o null si no esta bloqueada. */
  bloqueadaHasta: Date | null
}

/** Configuracion de la politica, tomada del entorno. */
export interface PoliticaBloqueo {
  /** Intentos fallidos antes de bloquear. */
  maxIntentos: number
  /** Minutos de duracion del bloqueo. */
  minutosDeBloqueo: number
}

/** Que hacer con un intento de login, segun el estado de la cuenta. */
export type DecisionBloqueo =
  | {
      /** Se puede intentar. */
      permitido: true
      /**
       * Intentos que quedan antes del bloqueo. Se usa para avisarle al
       * usuario ("te quedan 2 intentos") y para que el cliente no haga mas
       * requests inútiles.
       */
      intentosRestantes: number
    }
  | {
      /** La cuenta esta bloqueada. */
      permitido: false
      /** Instante en que se puede volver a intentar. */
      hasta: Date
      /** Minutos que faltan, para el mensaje al usuario. */
      minutosRestantes: number
    }

/**
 * Decide si un intento de login se permite.
 *
 * @param ahora Se pasa el instante en vez de llamar a `new Date()` adentro, por
 * dos razones: los tests pueden fijar el tiempo y no tienen que esperar de
 * verdad, y el service puede usar el mismo instante para toda la operacion.
 * Consultar el reloj dos veces en una misma funcion produce resultados
 * incoherentes en los bordes: una consulta dice "1 minuto restante" y la
 * siguiente "ya desbloqueada", en el mismo request.
 */
export function decidirSiPermitido(
  estado: EstadoBloqueo,
  politica: PoliticaBloqueo,
  ahora: Date,
): DecisionBloqueo {
  // Primero el bloqueo. El orden importa: una cuenta bloqueada no puede
  // "reintentarse" por el hecho de que el reloj ya paso, porque el desbloqueo
  // automatico ocurre con la fecha, no con un reset del contador.
  if (estado.bloqueadaHasta !== null && estado.bloqueadaHasta.getTime() > ahora.getTime()) {
    const minutosRestantes = Math.ceil(
      (estado.bloqueadaHasta.getTime() - ahora.getTime()) / 60_000,
    )

    return {
      permitido: false,
      hasta: estado.bloqueadaHasta,
      // `Math.ceil` y no un redondeo: con 30 segundos restantes tiene que
      // decir 1 minuto, no 0. Decir "0 minutos" mientras sigue bloqueado
      // invites a reintentar en un loop.
      minutosRestantes: Math.max(1, minutosRestantes),
    }
  }

  // La cuenta ya no esta bloqueada (o nunca lo estuvo). OJO: el chequeo de
  // arriba ya determino que la fecha paso, asi que se puede usar el contador
  // tal cual.
  const restantes = politica.maxIntentos - estado.intentosFallidos

  return {
    permitido: true,
    // Se acota en 0: un estado inconsistente (mas fallos que el maximo, por una
    // migracion o un cambio de configuracion) no debe dar negativos, que
    // romperian el mensaje "te quedan N intentos".
    intentosRestantes: Math.max(0, restantes),
  }
}

/**
 * Calcula el estado resultante de un intento FALLIDO.
 *
 * Se aplica el bloqueo en el ultimo intento, no en el que lo supera: con
 * maxIntentos = 5, el usuario tiene 5 chances y la sexta es la que bloquea.
 * Bloquear en el quinto haria que un usuario que se equivoca 5 veces seguidas y
 * despues se acuerda de la contrasena quede bloqueado igual, que es peor para
 * el usuario sin ganar nada en seguridad: el atacante que quiere probar la 6
 * ya esta bloqueado.
 *
 * @returns El estado nuevo, y si esta bloqueado.
 */
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

/**
 * Calcula el estado resultante de un intento EXITOSO.
 *
 * Se resetea el contador y SE BORRA la fecha de bloqueo.
 *
 * OJO con no borrar la fecha: si queda un `bloqueadaHasta` viejo en el futuro
 * junto con `intentosFallidos` en 0, la cuenta quedaria bloqueada sin motivo
 * visible en el contador, y el usuario no podria entrar aunque el panel de
 * admin diga que tiene 0 intentos fallidos. Un login correcto tiene que
 * limpiar las DOS columnas.
 */
export function registrarIntentoExitoso(): EstadoBloqueo {
  return { intentosFallidos: 0, bloqueadaHasta: null }
}

/**
 * Construye un mensaje para el usuario sin revelar si la cuenta existe.
 *
 * Esta es la parte de seguridad que se mezcla con la de usabilidad, y el
 * equilibrio importa:
 *
 * - Decir "ese email no existe" convierte el login en un enumerador de cuentas.
 * - Decir "contrasena incorrecta" cuando el email no existe tambien filtra,
 *   porque el usuario sabe que el email es el suyo.
 *
 * El mensaje correcto es el mismo para los dos casos de fallo, y la
 * diferenciacion se hace por tiempo (ver `verificarContrasena` en lib/password.ts,
 * que verifica contra un hash de referencia para que ambos casos tarden igual).
 *
 * @param intentosRestantes Se incluye solo si es mayor que 0, y solo en el
 * caso de contrasena incorrecta, que es donde el usuario puede hacer algo al
 * respecto. No se dice en "email no existe" porque el usuario no puede
 * corregirlo, y el mensaje le daria informacion de que el email no existe.
 */
export function mensajeDeCredencialesInvalidas(intentosRestantes: number): string {
  // Con un intento o menos, avisar es util: el usuario todavia puede usar
  // "olvide mi contrasena" antes de quedar afuera. Y tiene que decir cuantos
  // son, con singular incluido: un "quedan 1 intentos" delata que el mensaje es
  // una plantilla, que es justo lo que no queremos si estamos tratando de no
  // dar informacion sobre el estado de la cuenta.
  if (intentosRestantes === 1) {
    return 'Contrasena incorrecta. Queda 1 intento.'
  }

  if (intentosRestantes === 2) {
    return 'Contrasena incorrecta. Quedan 2 intentos.'
  }

  // Con 3 o mas intentos, se vuelve al mensaje generico. Cada intento restante
  // que se anuncia es informacion sobre el estado de la cuenta, y con 5
  // restantes el usuario no puede hacer nada con el dato: no esta en riesgo
  // ni hay nada que recuperar todavia.
  //
  // Y sobre todo: el generico tiene que ser IDENTICO al que devuelve
  // `errorDeCredenciales()` para el caso de email inexistente. Si difieren en
  // un solo caracter, el atacante distingue los dos casos. Ver la nota en
  // errors.ts, que explica como un punto de mas abrio ese oraculo.
  return MENSAJE_CREDENCIALES_INVALIDAS
}
