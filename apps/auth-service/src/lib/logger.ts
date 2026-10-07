

import pino from 'pino'
import { env, isProduction, isTest } from '../config/env.js'


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


export const MARCA_REDACTADA = '[REDACTED]'


export const logger = pino({
  level: env.LOG_LEVEL ?? (isTest ? 'silent' : isProduction ? 'info' : 'debug'),

  redact: {
    paths: RUTAS_REDACTADAS,
    censor: MARCA_REDACTADA,
    remove: false,
  },



  ...(isProduction
    ? {}
    : {
        transport: {
          target: 'pino-pretty',
          options: { colorize: true, translateTime: 'HH:MM:ss' },
        },
      }),




  timestamp: pino.stdTimeFunctions.isoTime,
})


export function crearLoggerConContexto(contexto: Record<string, unknown>) {
  return logger.child(contexto)
}


export function prefijoDeToken(token: string): string {
  return `${token.slice(0, 8)}...`
}
