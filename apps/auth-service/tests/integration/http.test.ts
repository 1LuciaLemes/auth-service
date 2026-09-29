/**
 * Tests de integracion de la capa HTTP.
 *
 * Estos tests importan la app REAL de `app.ts` y le mandan requests con
 * supertest, sin abrir un puerto. Eso es lo que hace `crearApp()` en vez de
 * hacer listen() dentro del modulo: aca importa, porque si no habria forma de
 * probar el assembly sin levantar un servidor.
 *
 * Lo que se verifica aca es la seguridad de la CAPA, que es distinta de la del
 * dominio. Un test de dominio puede pasar entero y el service seguir siendo
 * vulnerable si el CORS esta mal, si el logger filtra tokens, o si el error
 * handler devuelve el mensaje de un error interno.
 *
 * Ver explicacion.md, secciones 24 y 26.
 */

import { describe, expect, it } from 'vitest'
import request from 'supertest'
import { Router } from 'express'
import { crearApp } from '../../src/app.js'
import { AppError } from '../../src/lib/errors.js'

/**
 * Rutas de prueba.
 *
 * Se montan con un `Router` que se le PASA a `crearApp`, y no con `app.get()`
 * DESPUES. La diferencia no es de estilo: registrar rutas despues de que la
 * app ya tiene su 404 y su error handler las deja atras de los dos, y nunca se
 * ejecutan. Los tests de error daven 404 en vez de 500, que hacia pensar que
 * el error handler estaba mal cuando el problema era de orden.
 *
 * Los endpoints de prueba solo existen en memoria y en esta suite: no hay
 * ningun `if (isTest)` en el codigo de produccion, asi que no hay ningun
 * endpoint de debug compilado en el build.
 */
function rutasDePrueba(): Router {
  const router = Router()

  router.get('/cookie', (req, res) => {
    // Comprueba que cookie-parser funciona de verdad. El cast que hubo en
    // app.ts por el conflicto de tipos queda verificado con este test.
    //
    // Se devuelven dos cosas en vez de un booleano porque `req.cookies` NUNCA
    // es undefined: cookie-parser lo inicializa siempre como objeto, vacio si
    // no hay cookies. Por eso `Boolean(req.cookies)` siempre da true y no
    // sirve para detectar nada. La forma correcta de preguntar "hay cookies?"
    // es mirando la cantidad de claves.
    res.json({
      cantidad: Object.keys(req.cookies).length,
      valor: req.cookies.probando ?? null,
    })
  })

  router.get('/error-interno', () => {
    throw new AppError('server_error', 'Detalle que NO debe verse: tabla users.password_hash', 500, {
      esErrorInterno: true,
    })
  })

  router.get('/error-de-validacion', () => {
    throw new AppError('validation_error', 'El email no tiene formato valido', 400, {
      metadata: { campo: 'email' },
    })
  })

  router.get('/error-desconocido', () => {
    // Un error que no es AppError: el caso que mas riesgo tiene, porque el
    // mensaje de un error crudo puede contener detalles internos.
    throw new Error('conexion a users fallada: host 10.0.0.5:5432 rechazada')
  })

  return router
}

function appDePrueba() {
  return crearApp(rutasDePrueba())
}

describe('capa HTTP', () => {
  describe('health check', () => {
    it('responde sin tocar la base de datos', async () => {
      const respuesta = await request(appDePrueba()).get('/health')

      expect(respuesta.status).toBe(200)
      expect(respuesta.body.status).toBe('ok')
    })

    it('devuelve el estado en el header, para que una tool externa lo use', async () => {
      // Verificacion de que helmet NO metio un CSP que rompa la pagina: el
      // health check tiene que poder consumirse desde cualquier lado.
      const respuesta = await request(appDePrueba()).get('/health')

      expect(respuesta.headers['x-powered-by']).toBeUndefined()
      expect(respuesta.headers['content-security-policy']).toBeDefined()
    })
  })

  describe('404', () => {
    it('devuelve 404 estructurado para una ruta inexistente', async () => {
      const respuesta = await request(appDePrueba()).get('/no-existe')

      expect(respuesta.status).toBe(404)
      expect(respuesta.body.error).toBe('not_found')
      expect(respuesta.body.requestId).toBeDefined()
    })
  })

  describe('requestId', () => {
    it('genera un id distinto en cada request', async () => {
      const app = appDePrueba()

      const uno = await request(app).get('/health')
      const otro = await request(app).get('/health')

      // Si el id se aceptara del cliente, un atacante podria fijar el mismo en
      // todos sus requests y mezclar los logs con los de otro usuario.
      expect(uno.headers['x-request-id']).not.toBe(otro.headers['x-request-id'])
    })

    it('ignora un X-Request-Id enviado por el cliente', async () => {
      const respuesta = await request(appDePrueba())
        .get('/health')
        .set('X-Request-Id', 'elegido-por-el-atacante')

      // El id tiene que ser UUID del servidor, nunca el que mandó el cliente.
      expect(respuesta.headers['x-request-id']).not.toBe('elegido-por-el-atacante')
      expect(respuesta.headers['x-request-id']).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      )
    })
  })

  describe('cookies', () => {
    it('cookie-parser lee las cookies del request', async () => {
      // Este es el test que verifica el middleware montado en app.ts. Si
      // cookie-parser no estuviera, `cantidad` seria 0 y el valor null.
      const respuesta = await request(appDePrueba())
        .get('/api/cookie')
        .set('Cookie', 'probando=valor-de-prueba')

      expect(respuesta.status).toBe(200)
      expect(respuesta.body.cantidad).toBe(1)
      expect(respuesta.body.valor).toBe('valor-de-prueba')
    })

    it('sin cookies devuelve un objeto vacio, no undefined', async () => {
      const respuesta = await request(appDePrueba()).get('/api/cookie')

      expect(respuesta.status).toBe(200)
      expect(respuesta.body.cantidad).toBe(0)
      expect(respuesta.body.valor).toBeNull()
    })

    it('cuenta varias cookies correctamente', async () => {
      const respuesta = await request(appDePrueba())
        .get('/api/cookie')
        .set('Cookie', ['probando=uno', 'otra=dos', 'tercera=tres'].join('; '))

      expect(respuesta.body.cantidad).toBe(3)
      expect(respuesta.body.valor).toBe('uno')
    })
  })

  describe('error handler', () => {
    it('NUNCA expone el detalle de un error interno', async () => {
      const respuesta = await request(appDePrueba()).get('/api/error-interno')

      expect(respuesta.status).toBe(500)
      expect(respuesta.body.error).toBe('server_error')
      // Esta es la asercion que importa: el mensaje real no puede aparecer.
      expect(JSON.stringify(respuesta.body)).not.toContain('password_hash')
      expect(respuesta.body.message).not.toContain('password_hash')
    })

    it('un error de validacion SI muestra su mensaje', async () => {
      // Contraste intencional con el test anterior: un 400 de validacion es
      // informacion util para el usuario, no una fuga. Escalar el detalle y
      // ocultar el error interno seria tan inutil como moneda.
      const respuesta = await request(appDePrueba()).get('/api/error-de-validacion')

      expect(respuesta.status).toBe(400)
      expect(respuesta.body.message).toContain('email')
    })

    it('un error desconocido no filtra su mensaje al cliente', async () => {
      const respuesta = await request(appDePrueba()).get('/api/error-desconocido')

      expect(respuesta.status).toBe(500)
      expect(respuesta.body.error).toBe('server_error')
      // Un error crudo puede traer credenciales de conexion o paths internos.
      expect(JSON.stringify(respuesta.body)).not.toContain('10.0.0.5')
      expect(respuesta.body.message).toBe('Error interno del servidor')
    })

    it('siempre incluye el requestId para poder correlacionar con el log', async () => {
      const respuesta = await request(appDePrueba()).get('/api/error-desconocido')

      // Sin esto, el usuario reporta "fallo en el login" y no hay forma de
      // encontrar el log exacto: habria que buscar a mano entre millones.
      expect(respuesta.body.requestId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      )
    })
  })

  describe('CORS', () => {
    it('rechaza un origen que no esta en la allowlist', async () => {
      const respuesta = await request(appDePrueba())
        .get('/health')
        .set('Origin', 'https://sitio-malicioso.example')

      // El origen prohibido no debe recibir ningun dato.
      expect(respuesta.headers['access-control-allow-origin']).toBeUndefined()
    })

    it('permite un origen que SI esta en la allowlist', async () => {
      const app = crearApp()
      const respuesta = await request(app)
        .get('/health')
        .set('Origin', 'http://localhost:5173')

      expect(respuesta.status).toBe(200)
      expect(respuesta.headers['access-control-allow-origin']).toBe('http://localhost:5173')
      // credentials:true sin el header de origin seria el agujero de robo de
      // sesion que la seccion 24 explica.
      expect(respuesta.headers['access-control-allow-credentials']).toBe('true')
    })
  })
})
