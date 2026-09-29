/**
 * Logger estructurado con pino.
 *
 * Por que pino y no console.log (explicacion.md, seccion 26):
 *
 * El redact de campos sensibles es AUTOMATICO. Con console.log depende de que
 * yo me acuerde de no loguear un token cada vez que escribo una linea nueva, y
 * esa es una fuente de errores humanos que no tiene costo evitar. Aca la lista
 * de campos prohibidos se declara UNA vez, y de ahi en adelante ningun log
 * puede filtrar un secreto ni dejar de hacerlo.
 *
 * La segunda razon es que pino escribe JSON estructurado de forma nativa, que
 * es lo que necesita un agregador de logs real (Datadog, Loki, CloudWatch) para
 * poder indexar y filtrar por campo. Con console.log habria que parsear texto
 * libre, que es fragil.
 *
 * IMPORTANTE: los logs son un documento publico potencial. Si no lo podrias
 * dejar en un issue de GitHub, no lo loguees.
 */

import pino from 'pino'
import { env, isProduction, isTest } from '../config/env.js'

/**
 * Rutas de campos que se reemplazan por [REDACTED] en cualquier nivel.
 *
 * Se exporta para que los tests puedan construir un logger con esta misma
 * configuracion y comprobar que el redact funciona de verdad, en vez de
 * confiar en que la lista esta bien puesta. Ver tests/unit/logger.test.ts.
 *
 * Se listan en orden: si un objeto tiene `token`, se redacta entero, sin
 * importar que tenga adentro. Por eso los refresh tokens se loguean en un
 * campo propio llamado `tokenPrefijo`, y no en uno llamado `token`.
 *
 * `password` esta en la lista aunque hoy ningun endpoint lo loguee, porque la
 * lista es la red de seguridad: si manana alguien loguea el body de un request
 * de login "para debuggear", el password sale redactado igual.
 */
export const RUTAS_REDACTADAS = [
  'password',
  'passwordHash',
  'contrasena',
  'contrasenaHash',
  'token',
  'refreshToken',
  'accessToken',
  'idToken',
  'code',
  'codeVerifier',
  'secret',
  'clientSecret',
  'clientSecretHash',
  'authorization',
  'apiKey',
  'privateKey',
  'sessionId',
  'cookies',
  'req.headers.authorization',
  'req.headers.cookie',
  'request.headers.authorization',
  'request.headers.cookie',
]

/** El valor con el que se reemplaza todo campo sensible. */
export const MARCA_REDACTADA = '[REDACTED]'

/**
 * El logger raiz.
 *
 * `redact` de pino recibe rutas con sintaxis de punto para llegar a campos
 * anidados, y `censor` reemplaza el valor por el marcador. Con
 * `remove: false` el campo sigue existiendo pero con el valor censurado, que es
 * mejor que borrarlo: se sigue viendo que el campo estaba, y eso ayuda a
 * entender un bug sin exponer el contenido.
 */
export const logger = pino({
  level: env.LOG_LEVEL ?? (isTest ? 'silent' : isProduction ? 'info' : 'debug'),

  redact: {
    paths: RUTAS_REDACTADAS,
    censor: MARCA_REDACTADA,
    remove: false,
  },

  // En produccion, JSON en una linea. En desarrollo, texto con colores, que
  // es mas legible para alguien que esta leyendo la terminal.
  ...(isProduction
    ? {}
    : {
        transport: {
          target: 'pino-pretty',
          options: { colorize: true, translateTime: 'HH:MM:ss' },
        },
      }),

  // Timestamp ISO 8601. Es lo que esperan los agregadores de logs, y ademas
  // es legible para una persona: '2026-09-29T18:30:00.000Z' no necesita
  // conversion para entenderse.
  timestamp: pino.stdTimeFunctions.isoTime,
})

/**
 * Un logger con contexto fijo.
 *
 * Sirve para anadir identificadores a todos los logs de un ambito sin
 * pasarlos uno por uno. Por ejemplo, dentro del modulo de autenticacion:
 *
 *   const log = crearLoggerConContexto({ modulo: 'auth' })
 *   log.info('login exitoso', { userId })
 *
 * Asi el campo `modulo` aparece automaticamente en cada linea, y en el
 * agregador se puede filtrar facil.
 */
export function crearLoggerConContexto(contexto: Record<string, unknown>) {
  return logger.child(contexto)
}

/**
 * Forma segura de mostrar parte de un token en un log.
 *
 * Sirve para debugging: poder distinguir "este token es el mismo que el de
 * antes" sin exponer el token entero. Se muestran los primeros 8 caracteres, que
 * es lo que se necesita para correlacionar, y nunca el resto.
 *
 * Es la excepcion controlada a la regla de "no loguees tokens": lo que se
 * loguea no es el token, es un fragmento que no sirve para autenticarse.
 */
export function prefijoDeToken(token: string): string {
  return `${token.slice(0, 8)}...`
}
