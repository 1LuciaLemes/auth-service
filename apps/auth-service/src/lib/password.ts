/**
 * Hash de contrasenas con Argon2id.
 *
 * Por que Argon2id y no SHA-256 (explicacion.md, secciones 3 y 4):
 *
 * SHA-256 es ridiculamente rapido: microsegundos, 1 CPU, cero memoria. Un
 * atacante con una GPU hace miles de millones por segundo, y para el atacante
 * la velocidad es una ventaja.
 *
 * Argon2id es memory-hard: esta disenado para ser lento Y consumir memoria a
 * proposito. Esa asimetria es el diseno de seguridad:
 *
 *   yo hago login una vez y tardo ~100 ms, imperceptible para un humano
 *   el atacante quiere probar 100 millones de contrasenas, y cada intento
 *   le cuesta 100 ms y 64 MB. No puede: no tiene la RAM ni el tiempo.
 *
 * La regla general del proyecto: la lentitud se paga SOLAMENTE cuando el
 * atacante puede elegir el input. Si el input lo genera el servidor con
 * entropia suficiente (refresh tokens, codigos), se usa SHA-256, que es
 * rapido y ademas buscable en la base de datos.
 *
 * NOTA SOBRE EL SALT: no hay columna `salt` en la tabla users, y no es un
 * olvido. Argon2 genera el salt internamente y lo embebe en el string que
 * devuelve, junto con los parametros usados:
 *
 *   $argon2id$v=19$m=65536,t=3,p=4$<salt-base64>$<hash-base64>
 *
 * Eso tiene tres ventajas:
 *
 *   1. No hay columna salt que alguien pueda olvidar generar.
 *   2. Al verificar, argon2 lee los parametros del string. Si manana subimos
 *      la memoria de 64 MB a 128 MB, las contrasenas viejas siguen
 *      verificandose con los parametros viejos y no hay que rehashear nada:
 *      se rehashean solas en el proximo login exitoso.
 *   3. Es el formato estándar PHC, portable entre implementaciones.
 *
 * Ver explicacion.md, seccion 2.
 */

import { Algorithm, hash, verify } from '@node-rs/argon2'

/**
 * Parametros de Argon2id.
 *
 * Los valores no son arbitrarios. Vienen de las recomendaciones de OWASP
 * (2024), que apuntan al balance entre seguridad y costo:
 *
 *   memoryCost: 19456 KiB (19 MB)
 *     El parametro que define si el ataque con GPU es viable. Cada intento
 *     concurrente del atacante consume esta cantidad. En una GPU con 24 GB, un
 *     atacante puede ejecutar del orden de 1.200 intentos en paralelo. Con
 *     SHA-256 sin coste de memoria, el mismo equipo ejecuta millones.
 *
 *   timeCost: 2
 *     Cuantas veces se recorre la memoria. El costo total es memoryCost x
 *     timeCost, y es el segundo factor que frena la paralelizacion.
 *
 *   parallelism: 1
 *     Hilos por hash. En un serverless cada peticion es un proceso aparte y
 *     con varios nucleos disponibles, un parallelism alto permitiria que un
 *     atacante use una sola peticion para saturar la CPU. Con 1, cada intento
 *     queda acotado a un hilo y el atacante necesita muchas peticiones.
 *
 *   outputLen: 32 bytes
 *     256 bits de salida, el estandar para Argon2id.
 *
 * Si alguna vez se suben estos valores, es para endurecer contra hardware
 * dedicado. El costo es que cada login del usuario legitimo tambien se
 * vuelve mas lento, y ese es el trueque de siempre.
 *
 * El tipo NO es `as const` a proposito: hace falta que los campos sean
 * `number` normales, no literales, para que la comparacion de
 * `necesitaRehash` sea una comparacion de verdad y no una deduccion de
 * tipos que siempre da `false`.
 */
const PARAMETROS_ARGON2 = {
  algorithm: Algorithm.Argon2id,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
  outputLen: 32,
}

/** Los parametros actuales, exportados para que los tests los referencien. */
export const parametrosArgon2 = PARAMETROS_ARGON2

/**
 * Hashea una contrasena.
 *
 * El salt lo genera argon2 internamente, asi que no hay nada que pasar.
 *
 * @returns El hash en formato PHC, listo para guardar en users.password_hash.
 */
export async function hashearContrasena(contrasena: string): Promise<string> {
  return hash(contrasena, PARAMETROS_ARGON2)
}

/**
 * Verifica una contrasena contra un hash guardado.
 *
 * @returns true si coinciden, false si no.
 *
 * IMPORTANTE sobre los errores: esta funcion NUNCA debe lanzar. Si el hash
 * guardado esta corrupto, o si tiene parametros que argon2 no reconoce,
 * `verify` tira una excepcion. Un error de base de datos no debe convertirse
 * en un 500 en el endpoint de login, y sobre todo no debe distinguishlo de un
 * password incorrecto a ojos del atacante. Por eso el catch devuelve false:
 * para el llamador, un hash ilegible es indistinguible de una contrasena
 * equivocada, que es exactamente lo que queremos.
 */
export async function verificarContrasena(
  hashGuardado: string,
  contrasena: string,
): Promise<boolean> {
  try {
    return await verify(hashGuardado, contrasena)
  } catch {
    // Hash corrupto, parametros desconocidos o formato invalido.
    // Se trata como "no coincide". El detalle real se loguea en el audit log
    // desde el llamador, nunca desde aca, porque aca no hay contexto de
    // request ni de usuario.
    return false
  }
}

/**
 * Constante para verificar contra un hash que no existe.
 *
 * Existe para una defensa concreta: el **timing attack por enumeracion de
 * usuarios**.
 *
 * El problema: `argon2id.verify` tarda ~100 ms. Si el usuario no existe y el
 * login responde en 2 ms, un atacante mide el tiempo de respuesta y concluye
 * "ese email no esta registrado" (2 ms) o "esta registrado pero me equivoque de
 * contrasena" (100 ms). Eso convierte el endpoint de login en un enumerador de
 * cuentas, sin necesitar crackear un solo hash.
 *
 * La defensa: cuando el usuario no existe, se verifica igualmente contra un
 * hash fijo. La respuesta tarda lo mismo, y el atacante no puede distinguir los
 * dos casos. Es el mismo motivo por el que las respuestas de error son
 * genericas: la version temporal de "no revelar si el email existe".
 *
 * El hash se calcula UNA vez al cargar el modulo, no en cada login: hashearlo
 * en cada request seria agregar otros 100 ms, y solo hace falta que exista
 * como referencia.
 */
let hashDeReferencia: string | null = null

/** Hash de una contrasena aleatoria, usado solo como referencia de tiempo. */
export async function inicializarHashDeReferencia(): Promise<void> {
  // La contrasena no importa: no se va a comparar con nada real, solo se usa
  // para que verify tenga contra que correr y tarde lo mismo que un caso real.
  hashDeReferencia = await hashearContrasena('valor-aleatorio-solo-para-igualar-tiempos')
}

/**
 * Simula el costo de un verify real, para cuando el usuario no existe.
 *
 * Si por algun motivo `inicializarHashDeReferencia` no se llamo (por ejemplo en
 * un test aislado), se genera uno aca. El objetivo es que nunca se pueda
 * omitir la igualacion de tiempo por un forgot de inicializacion.
 */
export async function verificarContraReferencia(contrasena: string): Promise<void> {
  if (hashDeReferencia === null) {
    await inicializarHashDeReferencia()
  }

  // Se asigna a una variable local para que TypeScript sepa que, despues del
  // if de arriba, el valor no es null. Sin esto, TS no puede estrechar el tipo
  // de la variable de modulo a traves del await.
  const referencia = hashDeReferencia ?? (await hashearContrasena('respaldo'))

  // Se descarta el resultado: lo que importa es el tiempo que tardo.
  await verificarContrasena(referencia, contrasena)
}

/**
 * Devuelve si una contrasena necesita ser rehasheada.
 *
 * Esto resuelve un problema real de los parametros de Argon2: si manana se
 * suben de 19 MB a 64 MB, las contrasenas ya guardadas se calcularon con los
 * parametros viejos. No es un problema de seguridad inmediato, pero si lo es a
 * medio plazo, porque el costo por intento del atacante se mantiene bajo.
 *
 * La solucion es rehashear en el momento en que el usuario se loguea y ya
 * tenemos la contrasena en texto plano disponible, que es el unico momento
 * en que se puede. El costo para el usuario es un hash mas, y el beneficio es
 * que la base va migrando sola hacia los parametros fuertes.
 *
 * Se compara por PARAMETROS, no por el hash en si: dos llamadas a argon2 con
 * los mismos parametros producen el mismo resultado, asi que la comparacion
 * tiene que ser sobre memoryCost, timeCost y parallelism.
 */
export function necesitaRehash(hashGuardado: string): boolean {
  // Formato PHC: $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
  // SeCapturan m (memoria), t (iteraciones) y p (paralelismo).
  const patron = /\$argon2id\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$/
  const encontrado = hashGuardado.match(patron)

  // Si no se puede leer el formato, se asume que hay que rehashear: es la
  // postura segura ante la duda. Un hash que no se entiende no se puede
  // garantizar que tenga los parametros correctos.
  if (!encontrado) return true

  const memoriaGuardada = Number(encontrado[1])
  const iteracionesGuardadas = Number(encontrado[2])
  const paralelismoGuardado = Number(encontrado[3])

  // Cualquier parametro por debajo del actual requiere rehash.
  return (
    memoriaGuardada < PARAMETROS_ARGON2.memoryCost ||
    iteracionesGuardadas < PARAMETROS_ARGON2.timeCost ||
    paralelismoGuardado !== PARAMETROS_ARGON2.parallelism
  )
}
