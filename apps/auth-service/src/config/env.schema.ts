/**
 * Variables de entorno tipadas y validadas.
 *
 * Por que este archivo existe (explicacion.md, seccion 31):
 *
 * Las variables de entorno son strings. Nada garantiza que el valor sea
 * correcto, y el error aparece en produccion a las 3 de la mañana. TypeScript
 * no ayuda aca: los tipos se borran al compilar, y `process.env.PORT` siempre
 * es `string | undefined`.
 *
 * La solucion es declarar un schema de Zod y parsearlo al arrancar, antes de
 * hacer nada. Si algo falta o esta mal, el proceso muere en el arranque con un
 * mensaje claro, en vez de fallar en produccion.
 *
 * El `parse` se ejecuta al importar el modulo, que es exactamente lo que
 * queremos: si el server arranca, entonces `env` ya fue validado. El fallo es
 * inmediato y ruidoso.
 */

import { z } from 'zod'

/**
 * Convierte "http://a.com,http://b.com" en un array de strings.
 *
 * Es comodo tener la allowlist de CORS como una sola variable en el .env
 * en lugar de repetir el nombre de la variable N veces.
 */
const listaDeOrigenes = z
  .string()
  .transform((valor) =>
    valor
      .split(',')
      .map((origen) => origen.trim())
      .filter(Boolean),
  )
  .refine((lista) => lista.length > 0, {
    message: 'ALLOWED_ORIGINS tiene que tener al menos un origen',
  })

/** Un solo origen de redirect URI, usado en la configuracion de Google. */
const urlValida = z.string().url('Tiene que ser una URL valida')

/**
 * El schema, exportado para poder testearlo sin tocar process.env.
 *
 * Se exporta el schema y no solo el resultado del parseo, porque los tests
 * necesitan probar muchos casos (valido, invalido, que falta) sin que uno
 * pise el entorno del otro.
 */
export const EnvSchema = z
  .object({
    // ---------------------------------------------------------
    // Aplicacion
    // ---------------------------------------------------------
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().default(3000),

    /**
     * URL publica del service. Es exactamente el mismo valor que el issuer
     * del JWT, y a proposito son una sola variable: si se pudiera poner
     * distinto, los tokens de un entorno valarian en el otro y el cliente
     * no podria saber de que servidor vienen. Ver explicacion.md, seccion 18.
     */
    APP_URL: urlValida.default('http://localhost:3000'),

    // ---------------------------------------------------------
    // Base de datos
    // ---------------------------------------------------------
    /**
     * El mismo valor sirve para el Postgres local de Docker y para Neon en
     * produccion. Por eso el codigo no tiene que saber donde esta la base.
     */
    DATABASE_URL: z.string().min(1, 'DATABASE_URL es obligatoria'),

    // ---------------------------------------------------------
    // JWT: llaves para firmar los access tokens
    // ---------------------------------------------------------
    /**
     * La llave privada. NUNCA sale del servidor ni se sube al repositorio.
     * Vive en el .env local y en las Environment Variables de Vercel.
     *
     * OJO: en Windows el .env declara las llaves multilinea entre comillas
     * dobles. Sin comillas, el parser corta en el primer salto de linea y
     * la llave llega incompleta.
     */
    JWT_PRIVATE_KEY: z.string().min(1, 'JWT_PRIVATE_KEY es obligatoria'),

    /**
     * La llave publica. Se expone sin riesgo en /.well-known/jwks.json para
     * que cualquier resource server pueda validar nuestros tokens.
     */
    JWT_PUBLIC_KEY: z.string().min(1, 'JWT_PUBLIC_KEY es obligatoria'),

    /**
     * Identificador de la llave. Viaja en el header del JWT y es lo que
     * permite rotar llaves sin downtime: se genera un par nuevo, se cambia
     * este valor, y se publican las dos en el jwks.json.
     * Ver explicacion.md, seccion 7.
     */
    JWT_KEY_ID: z.string().min(1).default('key-local-01'),

    // ---------------------------------------------------------
    // Duracion de los tokens
    // ---------------------------------------------------------
    /**
     * Access token: corto a proposito, porque NO es revocable.
     * Ver explicacion.md, seccion 5.
     */
    ACCESS_TOKEN_TTL: z.string().default('15m'),

    /**
     * Refresh token: largo, porque SI es revocable (esta en la base de datos).
     */
    REFRESH_TOKEN_TTL: z.string().default('30d'),

    /**
     * Authorization code: muy corto y de un solo uso. Minima ventana posible.
     */
    AUTH_CODE_TTL: z.string().default('60s'),

    /** Token de verificacion de email. */
    EMAIL_VERIFICATION_TTL: z.string().default('24h'),

    /**
     * Token de reset de contrasena: expiracion corta, porque es el dato mas
     * sensible del sistema. Un token de reset que vive una semana es una
     * puerta abierta.
     */
    PASSWORD_RESET_TTL: z.string().default('15m'),

    // ---------------------------------------------------------
    // CORS
    // ---------------------------------------------------------
    /**
     * Lista blanca de origenes permitidos.
     *
     * NUNCA usar `*` con credenciales habilitadas: seria un agujero de robo
     * de sesion, porque cualquier web del mundo podria llamar al service con
     * las credenciales del usuario. Ver explicacion.md, seccion 24.
     */
    ALLOWED_ORIGINS: listaDeOrigenes,

    // ---------------------------------------------------------
    // Rate limiting
    // ---------------------------------------------------------
    /**
     * Que implementacion del limitador usar.
     *
     *   memory  = desarrollo y tests. No necesita nada externo.
     *   upstash = produccion. Obligatorio en Vercel, porque las instancias
     *             se reciclan y un contador en RAM volveria a cero en cada
     *             request, dejando el limite sin efecto.
     *
     * Ver explicacion.md, seccion 20 y la nota de decisiones de abajo.
     */
    RATE_LIMIT_STORE: z.enum(['memory', 'upstash']).default('memory'),

    /**
     * Credenciales de Upstash. Solo hacen falta si RATE_LIMIT_STORE=upstash.
     *
     * La validacion cruzada se hace mas abajo con superRefine: si elegiste
     * upstash y faltan estas dos, el arranque tiene que fallar, no esperar
     * al primer request.
     */
    UPSTASH_REDIS_REST_URL: z.string().url().optional(),
    UPSTASH_REDIS_REST_TOKEN: z.string().min(1).optional(),

    /** Intentos fallidos por email antes de bloquear la cuenta. */
    LOGIN_MAX_ATTEMPTS_PER_EMAIL: z.coerce.number().int().positive().default(5),

    /** Minutos de bloqueo cuando se supera el limite. */
    LOGIN_LOCKOUT_MINUTES: z.coerce.number().int().positive().default(15),

    /** Requests por IP por minuto, en todos los endpoints. */
    RATE_LIMIT_REQUESTS_PER_MINUTE: z.coerce.number().int().positive().default(20),

    // ---------------------------------------------------------
    // Email (Resend)
    // ---------------------------------------------------------
    RESEND_API_KEY: z.string().min(1, 'RESEND_API_KEY es obligatoria'),
    EMAIL_FROM: z.string().min(1, 'EMAIL_FROM es obligatorio'),
    EMAIL_FROM_NAME: z.string().default('Auth Service'),

    // ---------------------------------------------------------
    // Login social con Google (version 2)
    // ---------------------------------------------------------
    /**
     * El client_id es publico por diseno: viaja en el bundle del navegador
     * y no representa ningun riesgo. El client_secret es lo que no puede
     * salir del servidor. Ver explicacion.md, seccion 8.
     */
    GOOGLE_CLIENT_ID: z.string().default(''),
    GOOGLE_CLIENT_SECRET: z.string().default(''),
    GOOGLE_REDIRECT_URI: urlValida.default('http://localhost:3000/auth/google/callback'),
  })
  /**
   * Validaciones que dependen de otras variables. Con `.superRefine` se puede
   * decir "si elegiste esta opcion, entonces estas otras tienen que estar".
   *
   * Sin esto, un deploy con RATE_LIMIT_STORE=upstash y sin credenciales
   * arrancaria bien y recien fallaria en el primer request, con el rate limit
   * desactivado. Es exactamente el tipo de fallo silencioso que este archivo
   * existe para evitar.
   */
  .superRefine((valores, ctx) => {
    if (valores.RATE_LIMIT_STORE === 'upstash') {
      if (!valores.UPSTASH_REDIS_REST_URL) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['UPSTASH_REDIS_REST_URL'],
          message:
            'Es obligatoria si RATE_LIMIT_STORE=upstash. Sin ella el rate limit no funciona.',
        })
      }
      if (!valores.UPSTASH_REDIS_REST_TOKEN) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['UPSTASH_REDIS_REST_TOKEN'],
          message: 'Es obligatoria si RATE_LIMIT_STORE=upstash.',
        })
      }
    }
  })

/**
 * Tipo del entorno, derivado del schema.
 *
 * La direccion de la derivacion importa: el schema es la fuente de verdad y el
 * tipo sale de el, nunca al reves. Si el tipo estuviera declarado a mano y el
 * schema cambiara, se desincronizarian en silencio.
 *
 * Este archivo solo declara el schema. El parseo de process.env vive en
 * env.ts, para que este modulo se pueda importar en los tests sin que falle
 * por falta de variables reales en el entorno.
 */
export type Env = z.infer<typeof EnvSchema>

/**
 * Formato de las variables de entorno para imprimir en un error legible.
 * Solo se usa en desarrollo, para que el error diga "falta X" en vez de
 * soltar un objeto de Zod.
 */
export function formatearErroresDeEntorno(error: z.ZodError): string {
  return error.issues
    .map((issue) => {
      const variable = issue.path.join('.')
      return `  - ${variable}: ${issue.message}`
    })
    .join('\n')
}
