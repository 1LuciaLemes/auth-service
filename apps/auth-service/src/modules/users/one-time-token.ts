/**
 * One-time tokens: verificacion de email y reset de contrasena.
 *
 * Un one-time token es un texto aleatorio que se le manda al usuario por email
 * y que sirve una sola vez para demostrar que el email es suyo. La logica
 * completa vive aqui; el email y los endpoints son otra historia.
 *
 * La regla que gobierna TODO este modulo es una sola:
 *
 *   LA BASE GUARDA EL HASH. EL USUARIO RECIBE EL TOKEN EN CLARO.
 *
 * No es una preferencia de estilo, es la unica forma de que funcione. El token
 * viaja por el email, que pasa por servidores ajenos, queda en la bandeja de
 * entrada, aparece en notificaciones del sistema operativo y a veces en logs.
 * Si se guardara en claro, cualquiera que llegara hasta la fila de la base
 * tendria un token de reset de contrasena valido para cualquier cuenta.
 * Guardando el SHA-256, obtener la fila no sirve de nada: el hash no se puede
 * convertir de vuelta en el token original.
 *
 * Ver explicacion.md, secciones 32 y 36.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'

/** Para que se usa el token. Un token de un tipo NUNCA sirve para el otro. */
export type PropositoToken = 'email_verification' | 'password_reset'

/**
 * TTI de cada proposito.
 *
 *   - email_verification: 24 horas. No es urgente, y una vigencia corta
 *     convierte el registro en una molestia.
 *   - password_reset: 15 minutos. Es el token mas sensible de los dos, asi que
 *     es el que mas rapido tiene que morir.
 *
 * Que el de reset expire antes NO es un detalle: si durara lo mismo que el de
 * verificacion, un atacante que se interpusiera en el email tendria una
 * ventana de un dia entero para fijar una contrasena que el usuario todavia no
 * sabe que perdio.
 */
const TTL_POR_PROPOSITO: Record<PropositoToken, number> = {
  email_verification: 24 * 60 * 60,
  password_reset: 15 * 60,
}

/** Una fila de one_time_tokens, ya pasada por la base. */
export interface TokenAlmacenado {
  userId: string
  purpose: string
  tokenHash: string
  expiresAt: Date
  usedAt: Date | null
}

/** Lo que se devuelve al pedir un token nuevo. */
export interface TokenEmitido {
  /**
   * El token EN CLARO. Solo se usa para mandarlo por email, y se descarta
   * enseguida. Nunca se persiste ni se registra.
   */
  token: string
  /** SHA-256 del token. Esto es lo unico que va a la base. */
  tokenHash: string
  expiresAt: Date
  purpose: PropositoToken
}

/**
 * Genera un token de un solo uso.
 *
 * @returns El token en claro y su hash. El caller manda el token por email y
 * persiste solo el hash.
 */
export function generarTokenDeUnSoloUso(proposito: PropositoToken, ahora = new Date()): TokenEmitido {
  // 32 bytes aleatorios en base64url. En un solo intento, probando todos los
  // caracteres posibles, hay 2^256 combinaciones: buscar una por fuerza bruta
  // es fisicamente imposible, ni con todos los servidores del mundo en
  // paralelo.
  //
  // OJO: NO se usa Math.random, ni uuid, ni un contador. Math.random no es
  // criptografico y se puede predecir; un contador es adivinable por definicion.
  // randomBytes es el unico aceptable.
  const token = randomBytes(32).toString('base64url')

  return {
    token,
    tokenHash: hashearToken(token),
    expiresAt: new Date(ahora.getTime() + TTL_POR_PROPOSITO[proposito] * 1000),
    purpose: proposito,
  }
}

/** SHA-256 en hexadecimal. Determinista: el mismo token da el mismo hash. */
export function hashearToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex')
}

/**
 * Compara dos hashes en tiempo CONSTANTE.
 *
 * Un `===` sobre cadenas devuelve false en cuanto encuentra el primer caracter
 * distinto, y el tiempo que tarda depende de cuantos caracteres coincidieron.
 * Medir eso permite reconstruir un hash caracter a caracter. `timingSafeEqual`
 * compara siempre entero, coincida o no.
 */
export function hashesCoinciden(a: string, b: string): boolean {
  // Se comparan como Buffers de la MISMA longitud. `timingSafeEqual` lanza
  // si los tamanios difieren, y ese `length` es informacion que un atacante
  // tambien podria usar, asi que se compara tambien la longitud antes.
  const bufferA = Buffer.from(a, 'utf8')
  const bufferB = Buffer.from(b, 'utf8')

  if (bufferA.length !== bufferB.length) return false

  return timingSafeEqual(bufferA, bufferB)
}

/** Por que no se pudo canjear un token. Sirve para el audit log. */
export type MotivoTokenInvalido =
  | 'no_existe'
  | 'ya_usado'
  | 'expirado'
  | 'proposito_distinto'

/** Resultado de intentar canjear un token. */
export type ResultadoCanje =
  | { ok: true; userId: string }
  | { ok: false; motivo: MotivoTokenInvalido }

/**
 * Decide si un token se puede canjear, y para que.
 *
 * Es una funcion PURA a proposito: recibe la fila y devuelve el veredicto, sin
 * tocar la base. Asi se puede testear toda la matriz de casos sin levantar
 * PostgreSQL, que es justo lo que no se puede hacer en esta maquina.
 *
 * El llamador es el responsable de hacer el canje de forma ATOMICA. Hay una
 * trampa que se explica en la nota de `marcarTokenComoUsado`.
 *
 * @param row La fila encontrada por `tokenHash`. Null si no existe.
 * @param purposeQueSePide El purpose que el endpoint espera. Un token de
 * verificacion no puede canjearse en el endpoint de reset.
 * @param ahora Se pasa para que los tests puedan fijar el reloj. Por defecto es
 * la hora real. Se hace parametro y NO una variable de modulo porque un reloj
 * global mutable obliga a los tests a restaurar el estado y es la forma
 * habitual de que un test de un modulo rompa otro que corre despues.
 */
export function decidirCanje(
  row: TokenAlmacenado | null,
  purposeQueSePide: PropositoToken,
  ahora: Date = new Date(),
): ResultadoCanje {
  if (!row) return { ok: false, motivo: 'no_existe' }

  // usedAt != null significa que ya se canjeo. Un token es de UN SOLO USO, y
  // esto es lo que lo hace de un solo uso: sin esta comprobacion, un token
  // robado del email serviria para siempre.
  if (row.usedAt !== null) return { ok: false, motivo: 'ya_usado' }

  if (row.expiresAt.getTime() <= ahora.getTime()) return { ok: false, motivo: 'expirado' }

  // El purpose se valida SIEMPRE. Sin esta comprobacion, un token de reset de
  // contrasena podria usarse para "verificar" un email, o al reves. Las dos
  // operaciones son de riesgo distinto y no deben ser intercambiables.
  if (row.purpose !== purposeQueSePide) return { ok: false, motivo: 'proposito_distinto' }

  return { ok: true, userId: row.userId }
}

/** TTL en segundos de un proposito. Lo consume el endpoint para mostrarlo. */
export function ttlDeProposito(purpose: PropositoToken): number {
  return TTL_POR_PROPOSITO[purpose]
}
