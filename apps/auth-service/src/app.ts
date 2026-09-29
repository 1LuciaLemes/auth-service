/**
 * Assembly de la aplicacion Express.
 *
 * Esta funcion DEVUELVE la app, y no la levanta. Esa separacion es
 * deliberada: `server.ts` es el que hace `listen()`, y asi los tests de
 * integracion pueden importar la app y hacer requests contra ella con
 * supertest, sin abrir un puerto real ni tener que apagarlo despues.
 *
 * El ORDEN de los middlewares importa mucho, y no es arbitrario:
 *
 *   1. helmet        antes de todo: los headers de seguridad tienen que estar
 *                    puestos aunque el request falle despues
 *   2. contexto      genera el requestId, del que dependen todos los logs
 *   3. CORS          temprano, para que hasta los errores de validacion
 *                    lleven los headers de CORS y el browser los pueda leer
 *   4. cookieParser  antes de cualquier cosa que lea cookies
 *   5. body parser   con limite de tamaño, para no recibir un body de 50 MB
 *   6. rate limit    antes de la validacion, para que un flood de requests
 *                    malformados se corte antes de analizar cada uno
 *   7. rutas
 *   8. 404
 *   9. error handler SIEMPRE ultimo
 *
 * Ver explicacion.md, seccion 24.
 */

import express, { type Express, Router } from 'express'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import helmet from 'helmet'
import { env } from './config/env.js'
import { AppError } from './lib/errors.js'
import { manejarErrores } from './middleware/error-handler.js'
import { contextoDeRequest } from './middleware/request-context.js'

/**
 * @param rutas Router con los endpoints del service. Opcional, para que los
 * tests puedan montar sus rutas de prueba en la posicion correcta.
 */
export function crearApp(rutas?: Router): Express {
  const app = express()

  // Behind Vercel hay un proxy. Sin esto, `req.ip` devuelve la IP del proxy en
  // vez de la del usuario, y el rate limit por IP seria inútil: todos los
  // requests harian cuenta como si vinieran de la misma maquina.
  app.set('trust proxy', 1)
  app.disable('x-powered-by') // No hace falta decir que Express es el motor

  // --- 1. helmet ----------------------------------------------------
  //
  // Un detalle importante: helmet pone un CSP por defecto que rompe los
  // flujos OAuth. El popup de Google y la redireccion de /authorize necesitan
  // poder cargar en un frame y navegar a otro origen. Por eso se relaja
  // frameAncestors para el flujo de autorizacion, y no se toca nada mas.
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          // El flujo OAuth con popup necesita esto. Restringirlo a los origenes
          // de Google mantiene el beneficio de la proteccion sin romper el
          // login social.
          frameAncestors: ["'self'", 'https://accounts.google.com'],
        },
      },
      // La referrer policy por defecto puede filtrar el authorization code a
      // sitios terceros via el header Referer en la redireccion.
      referrerPolicy: { policy: 'no-referrer' },
    }),
  )

  // --- 2. contexto del request --------------------------------------
  app.use(contextoDeRequest)

  // --- 3. CORS ------------------------------------------------------
  //
  // Allowlist EXPLICITA de origenes. Nunca `origin: '*'`: combinado con
  // credentials en true, seria un agujero de robo de sesion, porque
  // cualquier web del mundo podria llamar al service con las credenciales del
  // usuario. Ver explicacion.md, seccion 24.
  app.use(
    cors({
      origin: (origin, callback) => {
        // Sin origin = request del mismo origen o una tool como curl.
        // No es un ataque de navegador, asi que se permite.
        if (!origin) {
          callback(null, true)
          return
        }

        if (env.ALLOWED_ORIGINS.includes(origin)) {
          callback(null, true)
          return
        }

        // Se rechaza con un error, no con un `false` silencioso. La diferencia
        // importa: con `false`, el navegador recibe un error generico de CORS
        // que no explica nada; con un error, el servidor registra el intento,
        // que es informacion de seguridad valuable.
        callback(new AppError('access_denied', 'Origen no permitido por CORS', 403))
      },
      // Necesario para que el navegador mande cookies de sesion.
      credentials: true,
      methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
      // Headers que el cliente puede mandar en un request con credenciales.
      allowedHeaders: ['Content-Type', 'Authorization'],
      // Headers que el navegador puede leer de la respuesta.
      exposedHeaders: ['X-Request-Id', 'Retry-After'],
      maxAge: 600,
    }),
  )

  // --- 4. cookies ----------------------------------------------------
  //
  // Sin cast, y vale la pena que quede escrito por que, porque el sintoma era
  // muy dificil de leer.
  //
  // `@types/cookie-parser@1.4.10` declara una dependencia de `@types/express@*`,
  // que en el momento de instalar resuelve a la 5.0.6. Como este service usa
  // Express 4, el proyecto tambien tenia su propia `@types/express@4.17.25`. npm
  // hoisteo la 5 a la raiz y dejo la 4 dentro de apps/auth-service, asi que
  // convivian DOS copias de los tipos de Express.
  //
  // Con dos copias, los `RequestHandler` de una no son el mismo tipo que los de
  // la otra, aunque tengan identica forma. Por eso el error de compilacion de
  // este `app.use` no hablaba de cookies: decia que el handler "no es
  // asignable a PathParams". `app.use` tiene muchas sobrecargas, y TypeScript
  // las va descartando una por una hasta que muestra la ultima, que espera un
  // path. El mensaje real (dos identidades de tipo distintas) queda escondido
  // detras de eso.
  //
  // Lo que se hizo NO fue un cast para silenciarlo, sino agregar un override en
  // el package.json de la raiz que fija `@types/express` en 4.17.25 para todo el
  // monorepo. Un cast habria escondido el problema y dejado las dos copias en
  // disco, que siguen causando errores confusos en el primer archivo que las
  // mezcle.
  app.use(cookieParser())

  // --- 5. body parser ------------------------------------------------
  // El limite de 100 KB es generoso para un login y chico para no recibir un
  // body enorme. Sin este limite, un atacante puede mandar 50 MB y agotar la
  // memoria del proceso.
  app.use(express.json({ limit: '100kb' }))
  app.use(express.urlencoded({ extended: false, limit: '100kb' }))

  // --- Health check ---------------------------------------------------
  // Lo primero que responde, y sin tocar la base de datos: lo usa el
  // orquestador de Vercel para decidir si la instancia esta viva, y no tiene
  // sentido que un chequeo de salud falle por un problema de base de datos.
  app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() })
  })

  // --- 6. rutas ------------------------------------------------------
  //
  // NOTA: el rate limit global se va a registrar entre el body parser y este
  // punto, cuando se implemente. Va ahi por una razon concreta: despues del
  // body parser, para no cortar los requests que mandaron un body bien
  // formado, y antes de las rutas, para que ningun handler llegue a hacer
  // trabajo con un request que ya excedio el limite.
  //
  // Las rutas del service se reciben como parametro y NO se registran aca una
  // por una. Es deliberado:
  //
  // Un primer intento era devolver la app y dejar que `server.ts` y los tests
  // registaran sus endpoints encima con `app.get(...)`. No funciona, y el
  // sintoma es dificil de leer: las rutas registradas despues nunca se
  // ejecutan, y los tests de error daven 404 en vez de 500. La razon es que
  // esta funcion ya registro el 404 y el error handler, que tienen que ser los
  // ULTIMOS; Express evalua en orden de registro, asi que una ruta agregada
  // despues ya quedo atras de los dos.
  //
  // Que el orden lo controle esta funcion y no quien llama es lo correcto, y
  // por una razon de seguridad: si cada quien pudiera montar sus middleware
  // donde quisiera, un endpoint nuevo podria quedar antes de la validacion, o
  // despues del rate limit cuando exista, y nadie lo notaria hasta que hubiera
  // un incidente.
  app.use('/api', rutas ?? Router())

  // --- 7. 404 -------------------------------------------------------
  // Si llego hasta aca, no hubo ninguna ruta que coincidiera. Va DESPUES de
  // las rutas y ANTES del error handler.
  app.use((req, _res, next) => {
    next(
      new AppError('not_found', `Ruta no encontrada: ${req.method} ${req.path}`, 404),
    )
  })

  // --- 7. error handler ----------------------------------------------
  // SIEMPRE el ultimo. Si se pone antes de las rutas, no lo atrapa Express y
  // los errores de los handlers llegan sin manejar.
  app.use(manejarErrores)

  return app
}
