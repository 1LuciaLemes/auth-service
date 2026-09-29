/**
 * Utilidades criptograficas.
 *
 * Este archivo tiene los tokens que el server genera y los hashes con los
 * que se guardan. La distincion entre "generar" y "hashear" aca es la misma
 * que atraviesa todo el proyecto (explicacion.md, seccion 4):
 *
 *   - Tokens que el SERVIDOR genera (refresh, auth code, verificacion, reset):
 *     se hashean con SHA-256. Son 256 bits de entropia, no hay diccionario que
 *     los ataque, y necesito poder buscarlos en la base por su valor. Con
 *     argon2 no podria indexarlos sin recorrer la tabla entera.
 *
 *   - Contrasenas que elige el USUARIO: argon2id. Ahi si hay diccionario y si
 *     hace falta la lentitud. Eso vive en lib/password.ts.
 *
 * Todos los valores aleatorios salen de `crypto` de Node, que es un CSPRNG
 * (generador criptograficamente seguro). Math.random() NO sirve para esto:
 * con la semilla correcta, sus salidas son predecibles, y un token predecible
 * es un token que se puede adivinar.
 */

import {
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto'

// ============================================================
// GENERACION DE VALORES ALEATORIOS
// ============================================================

/**
 * Genera un string aleatorio criptograficamente seguro, en base64url.
 *
 * Por que base64url y no base64 "normal": base64 usa los caracteres `+` y `/`,
 * que tienen que ir escapados cuando el valor va en una URL o en un query
 * string. base64url los reemplaza por `-` y `_`, y no necesita escaping.
 *
 * @param bytes Cuantos bytes de entropia. 32 bytes = 256 bits.
 */
export function generarToken(bytes: number = 32): string {
  return randomBytes(bytes).toString('base64url')
}

/**
 * Genera un UUID v4.
 *
 * Se usa para identificadores internos: id de usuario, id de sesion, familyId
 * de una familia de refresh tokens.
 *
 * OJO: un UUID NO es un secreto. Es un identificador, no una credencial. Se
 * genera con crypto porque es lo que hay disponible y porque no cuesta nada,
 * pero se puede leer a traves de logs, URLs y respuestas. Un refresh token
 * NUNCA es un UUID: es un string de 256 bits generado con randomBytes.
 */
export function generarId(): string {
  return randomUUID()
}

/**
 * Genera el `familyId` de una familia de refresh tokens.
 *
 * Es un UUID y no un token porque no es un secreto: identifica la familia para
 * poder revocarla en cascada, pero no da acceso a nada por si mismo. Quien
 * tenga el familyId no puede autenticarse; necesita un token de la familia.
 */
export function generarFamilyId(): string {
  return randomUUID()
}

// ============================================================
// HASHEO DE TOKENS
// ============================================================

/**
 * Hashea un token con SHA-256, en base64url.
 *
 * Esto es lo que se guarda en la base de datos. El token en claro solo existe
 * en la respuesta HTTP y en la memoria del cliente.
 *
 * Por que SHA-256 y no argon2id:
 *
 *   1. Seguridad: el token tiene 256 bits de entropia generados por el
 *      servidor. No hay diccionario, no hay GPU que sirva, no hay ataque.
 *      Argon2id no aportaria nada.
 *
 *   2. Funcionalidad (la razon que manda): el token llega en texto plano en
 *      cada request y hay que buscarlo. `WHERE token_hash = sha256(token)`.
 *      Con argon2id no se puede indexar ni comparar: habria que recorrer la
 *      tabla entera hasheando cada fila, y el endpoint de refresh se
 *      convertiria en un scan lentisimo.
 *
 * El riesgo que asuma es que si alguien logra accesar a la base, y ademas
 * logra bypasear el hash, tendria los tokens. Pero un SHA-256 de un valor
 * aleatorio de 256 bits no se puede invertir por fuerza bruta: el espacio de
 * busqueda es 2^256. Ver explicacion.md, seccion 4.
 */
export function hashearToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('base64url')
}

// ============================================================
// COMPARACION EN TIEMPO CONSTANTE
// ============================================================

/**
 * Compara dos strings en tiempo constante.
 *
 * El problema que resuelve: comparar strings con `===` es una operacion que
 * termina en el primer caracter que difiere. Eso filtra informacion por
 * timing: un atacante que mide cuanto tarda la comparacion puede deducir
 * cuantos caracteres iniciales coinciden. Con un hash, eso permitiria
 * reconstruir el valor byte a byte.
 *
 * `timingSafeEqual` compara TODOS los bytes siempre, sin cortarse, y devuelve
 * solo el resultado final.
 *
 * Donde se usa: comparar un `code_verifier` recibido contra un
 * `code_challenge` guardado, y cualquier comparacion de secretos.
 *
 * Trampa importante: `timingSafeEqual` tira error si los dos buffers tienen
 * distinta longitud. Hay que verificar el largo antes, o la excepcion misma
 * filtra informacion.
 */
export function compararEnTiempoConstante(a: string, b: string): boolean {
  const bufferA = Buffer.from(a, 'utf8')
  const bufferB = Buffer.from(b, 'utf8')

  if (bufferA.length !== bufferB.length) {
    return false
  }

  return timingSafeEqual(bufferA, bufferB)
}

// ============================================================
// PKCE  (explicacion.md, seccion 13)
// ============================================================

/**
 * Genera el `code_verifier` de PKCE.
 *
 * El code_verifier es el SECRETO del cliente. Se genera en el navegador, nunca
 * sale de la maquina del cliente hasta el momento de canjear el codigo, y el
 * servidor solo recibe su SHA-256 (el code_challenge).
 *
 * Longitud: 43 caracteres, el minimo que permite el RFC 7636 con SHA-256
 * truncado a 32 bytes en base64url (43 caracteres dan 256 bits). Se podria
 * llegar hasta 128 caracteres, y mas largo es mas seguro, pero 43 ya cumple
 * con el estandar y produce una URL razonable.
 */
export function generarCodeVerifier(): string {
  return generarToken(32)
}

/**
 * Calcula el `code_challenge` a partir de un `code_verifier`.
 *
 * S256 = BASE64URL(SHA-256(verifier)). Es la unica transformacion aceptada.
 * El metodo `plain` esta prohibido porque no transforma nada: el challenge
 * seria el mismo verifier, y entonces interceptar el challenge de la URL
 * seria equivalente a tener el secreto.
 *
 * Este calculo ocurre en el SERVIDOR, en el endpoint /token, para verificar
 * que el verifier que manda el cliente corresponde al challenge que se
 * registro en /authorize.
 */
export function calcularCodeChallenge(codeVerifier: string): string {
  return createHash('sha256').update(codeVerifier, 'utf8').digest('base64url')
}

/**
 * Verifica un par (code_verifier, code_challenge) de PKCE.
 *
 * El nucleo de la seguridad del flujo Authorization Code (explicacion.md,
 * seccion 13): si un atacante se queda con el authorization code pero no con
 * el code_verifier, no puede canjearlo, porque no puede producir un verifier
 * cuyo SHA-256 sea el challenge registrado.
 *
 * La comparacion es en tiempo constante para no filtrar informacion sobre
 * cuantos bytes del challenge coinciden.
 */
export function verificarPkce(codeVerifier: string, codeChallenge: string): boolean {
  return compararEnTiempoConstante(calcularCodeChallenge(codeVerifier), codeChallenge)
}

// ============================================================
// CONTRASENAS DE UN SOLO USO  (verificacion de email y reset)
// ============================================================

/**
 * Genera el token de un solo uso para verificar email o resetear contrasena.
 *
 * 32 bytes de entropia, igual que un refresh token. Se hashea con SHA-256
 * antes de guardarse.
 */
export function generarTokenDeUnSoloUso(): string {
  return generarToken(32)
}

// ============================================================
// NORMALIZACION DE EMAIL
// ============================================================

/**
 * Normaliza un email para poder compararlo y guardarlo de forma consistente.
 *
 * Por que hace falta: si se guardaran los emails tal cual, `Lucia@x.com` y
 * `lucia@x.com` serian dos cuentas distintas, que es exactamente el bug que el
 * account linking existe para evitar. Un usuario que se registra con una
 * capitalizacion y despues entra con otra terminaria con dos cuentas.
 *
 * Se pasa a minusculas y se recortan los espacios. Ojo: NO se hace nada mas.
 * No se quitan los puntos ni los aliases de Gmail, porque esos reglas
 * varian por proveedor, y cambiarlas seria peor que aceptarlas.
 *
 * El trim y el toLowerCase juntos cubren el caso real: el usuario pega el
 * email con un espacio de adelante por accidente.
 */
export function normalizarEmail(email: string): string {
  return email.trim().toLowerCase()
}
