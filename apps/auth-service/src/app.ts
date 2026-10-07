

import express, { type Express, Router } from 'express'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import helmet from 'helmet'
import { env } from './config/env.js'
import { AppError } from './lib/errors.js'
import { manejarErrores } from './middleware/error-handler.js'
import { contextoDeRequest } from './middleware/request-context.js'


export function crearApp(rutas?: Router): Express {
  const app = express()




  app.set('trust proxy', 1)
  app.disable('x-powered-by')







  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],



          frameAncestors: ["'self'", 'https://accounts.google.com'],
        },
      },


      referrerPolicy: { policy: 'no-referrer' },
    }),
  )


  app.use(contextoDeRequest)







  app.use(
    cors({
      origin: (origin, callback) => {


        if (!origin) {
          callback(null, true)
          return
        }

        if (env.ALLOWED_ORIGINS.includes(origin)) {
          callback(null, true)
          return
        }





        callback(new AppError('access_denied', 'Origen no permitido por CORS', 403))
      },

      credentials: true,
      methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],

      allowedHeaders: ['Content-Type', 'Authorization'],

      exposedHeaders: ['X-Request-Id', 'Retry-After'],
      maxAge: 600,
    }),
  )

























  app.use(cookieParser())





  app.use(express.json({ limit: '100kb' }))
  app.use(express.urlencoded({ extended: false, limit: '100kb' }))





  app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() })
  })

























  app.use('/api', rutas ?? Router())




  app.use((req, _res, next) => {
    next(
      new AppError('not_found', `Ruta no encontrada: ${req.method} ${req.path}`, 404),
    )
  })




  app.use(manejarErrores)

  return app
}
