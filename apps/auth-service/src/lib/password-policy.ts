/**
 * Politica de contrasenas.
 *
 * Una decision de seguridad que va en el servidor, no en el frontend. El
 * frontend puede mostrar las reglas para que el usuario las vea, pero la
 * validacion real ocurre aca, porque el frontend es una sugerencia y este es
 * el punto donde no se puede esquivar.
 *
 * La politica apunta a dos ataques concretos, no a reglas arbitrarias:
 *
 *   1. Credential stuffing (explicacion.md, seccion 21): el atacante prueba
 *      combinaciones filtradas de otros sitios. Contra eso ayuda la longitud
 *      y el rechazo de contrasenas ya conocidas.
 *
 *   2. Fuerza bruta con diccionario: si el usuario elige "123456", ningun
 *      rate limit salva la cuenta a largo plazo, porque el atacante tiene
 *      tiempo. Argon2id lo frena, pero no lo detiene. Rechazar las debiles de
 *      entrada es lo que de verdad las detiene.
 *
 * Lo que NO se hace, y es deliberado: no se exige un simbolo, un numero y una
 * mayuscula. Esas reglas empujan a la gente a escribir "Password1!", que
 * aparece en todos los diccionarios de contrasenas debiles. La longitud y la
 * ausencia de palabras conocidas dan mas resistencia real con menos friccion.
 * Ver la guia de NIST SP 800-63B.
 */

/**
 * Contrasenas mas usadas del mundo.
 *
 * Lista corta a proposito: no se busca ser exhaustivo. Si alguien elige una de
 * estas 20, la contrasena esta en cualquier diccionario de ataque. Ampliar la
 * lista es barato, pero mantenerla al dia no lo es, y una lista vieja es peor
 * que una lista chica y correcta.
 *
 * NOTA: esta es una lista de ejemplo para hacer el proyecto funcional. Para
 * produccion, lo correcto es usar la lista de contrasenas mas comunes que
 * publica Have I Been Pwned, que se actualiza y se puede consultar por API sin
 * exponer la contrasena del usuario (envia solo los primeros 5 caracteres en
 * hash k-anonimo).
 */
const CONTRASENAS_COMUNES = new Set([
  '123456',
  'password',
  '123456789',
  '12345678',
  '12345',
  '1234567',
  'qwerty',
  'abc123',
  '111111',
  '123123',
  'admin',
  'letmein',
  'monkey',
  'dragon',
  'iloveyou',
  'sunshine',
  'princess',
  'football',
  'baseball',
  'welcome',
  'contrasena',
  'password1',
])

/** Longitud minima. */
export const LONGITUD_MINIMA = 12

/**
 * Longitud maxima.
 *
 * No es un capricho: bcrypt trunca silenciosamente a 72 bytes, y hay que
 * dejar margen. El limite evita que alguien mande un string de 10 MB y gaste
 * memoria haciendo el hash.
 */
export const LONGITUD_MAXIMA = 128

/**
 * Resultado de evaluar una contrasena.
 *
 * Devuelve TODOS los problemas, no solo el primero, para que el usuario
 * corrija todo de una vez en vez de descubrir los problemas de a uno.
 */
export interface ResultadoValidacion {
  valida: boolean
  problemas: string[]
}

/**
 * Valida una contrasena contra la politica.
 *
 * @returns Los problemas encontrados. Si `problemas` esta vacio, es valida.
 */
export function validarContrasena(contrasena: string): ResultadoValidacion {
  const problemas: string[] = []

  if (contrasena.length < LONGITUD_MINIMA) {
    problemas.push(`La contrasena tiene que tener al menos ${LONGITUD_MINIMA} caracteres`)
  }

  if (contrasena.length > LONGITUD_MAXIMA) {
    problemas.push(`La contrasena no puede superar los ${LONGITUD_MAXIMA} caracteres`)
  }

  if (CONTRASENAS_COMUNES.has(contrasena.toLowerCase())) {
    problemas.push('Esa contrasena aparece en las listas de contrasenas mas usadas')
  } else {
    // Detecta variantes: "Password1" es tan debil como "password", porque
    // esta en todos los diccionarios igual.
    //
    // Va en un `else` y no como un check aparte a proposito: si la contrasena
    // ya esta en la lista, avisar ademas que es "variante" seria el mismo
    // motivo dicho dos veces, y el usuario veria un error que no puede
    // resolver de ninguna otra forma. Un problema, un mensaje.
    const sinDigitosNiSimbolos = contrasena
      .toLowerCase()
      .replace(/[0-9!@#$%^&*(),.?":{}|<>_\-+=[\]/\\;'`~]/g, '')

    if (CONTRASENAS_COMUNES.has(sinDigitosNiSimbolos)) {
      problemas.push('Esa contrasena es una variante de una contrasena muy usada')
    }
  }

  return { valida: problemas.length === 0, problemas }
}

/**
 * Indica si una contrasena seria aceptada.
 *
 * Atajo para los lugares donde solo hace falta el booleano.
 */
export function contrasenaEsValida(contrasena: string): boolean {
  return validarContrasena(contrasena).valida
}
