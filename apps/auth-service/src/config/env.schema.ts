

import { z } from 'zod'


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


const urlValida = z.string().url('Tiene que ser una URL valida')


export const EnvSchema = z
  .object({



    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().default(3000),


    LOG_LEVEL: z
      .enum(['silent', 'error', 'warn', 'info', 'debug'])
      .optional(),


    APP_URL: urlValida.default('http://localhost:3000'),





    DATABASE_URL: z.string().min(1, 'DATABASE_URL es obligatoria'),





    JWT_PRIVATE_KEY: z.string().min(1, 'JWT_PRIVATE_KEY es obligatoria'),


    JWT_PUBLIC_KEY: z.string().min(1, 'JWT_PUBLIC_KEY es obligatoria'),


    JWT_KEY_ID: z.string().min(1).default('key-local-01'),





    ACCESS_TOKEN_TTL: z.string().default('15m'),


    REFRESH_TOKEN_TTL: z.string().default('30d'),


    AUTH_CODE_TTL: z.string().default('60s'),


    EMAIL_VERIFICATION_TTL: z.string().default('24h'),


    PASSWORD_RESET_TTL: z.string().default('15m'),





    ALLOWED_ORIGINS: listaDeOrigenes,





    RATE_LIMIT_STORE: z.enum(['memory', 'upstash']).default('memory'),


    UPSTASH_REDIS_REST_URL: z.string().url().optional(),
    UPSTASH_REDIS_REST_TOKEN: z.string().min(1).optional(),


    LOGIN_MAX_ATTEMPTS_PER_EMAIL: z.coerce.number().int().positive().default(5),


    LOGIN_LOCKOUT_MINUTES: z.coerce.number().int().positive().default(15),


    RATE_LIMIT_REQUESTS_PER_MINUTE: z.coerce.number().int().positive().default(20),




    RESEND_API_KEY: z.string().min(1, 'RESEND_API_KEY es obligatoria'),
    EMAIL_FROM: z.string().min(1, 'EMAIL_FROM es obligatorio'),
    EMAIL_FROM_NAME: z.string().default('Auth Service'),





    GOOGLE_CLIENT_ID: z.string().default(''),
    GOOGLE_CLIENT_SECRET: z.string().default(''),
    GOOGLE_REDIRECT_URI: urlValida.default('http://localhost:3000/auth/google/callback'),
  })

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


export type Env = z.infer<typeof EnvSchema>


export function formatearErroresDeEntorno(error: z.ZodError): string {
  return error.issues
    .map((issue) => {
      const variable = issue.path.join('.')
      return `  - ${variable}: ${issue.message}`
    })
    .join('\n')
}
