

import { describe, expect, it } from 'vitest'
import request from 'supertest'
import { Router } from 'express'
import { crearApp } from '../../src/app.js'
import { AppError } from '../../src/lib/errors.js'


function rutasDePrueba(): Router {
  const router = Router()

  router.get('/cookie', (req, res) => {








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



      expect(uno.headers['x-request-id']).not.toBe(otro.headers['x-request-id'])
    })

    it('ignora un X-Request-Id enviado por el cliente', async () => {
      const respuesta = await request(appDePrueba())
        .get('/health')
        .set('X-Request-Id', 'elegido-por-el-atacante')


      expect(respuesta.headers['x-request-id']).not.toBe('elegido-por-el-atacante')
      expect(respuesta.headers['x-request-id']).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      )
    })
  })

  describe('cookies', () => {
    it('cookie-parser lee las cookies del request', async () => {


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

      expect(JSON.stringify(respuesta.body)).not.toContain('password_hash')
      expect(respuesta.body.message).not.toContain('password_hash')
    })

    it('un error de validacion SI muestra su mensaje', async () => {



      const respuesta = await request(appDePrueba()).get('/api/error-de-validacion')

      expect(respuesta.status).toBe(400)
      expect(respuesta.body.message).toContain('email')
    })

    it('un error desconocido no filtra su mensaje al cliente', async () => {
      const respuesta = await request(appDePrueba()).get('/api/error-desconocido')

      expect(respuesta.status).toBe(500)
      expect(respuesta.body.error).toBe('server_error')

      expect(JSON.stringify(respuesta.body)).not.toContain('10.0.0.5')
      expect(respuesta.body.message).toBe('Error interno del servidor')
    })

    it('siempre incluye el requestId para poder correlacionar con el log', async () => {
      const respuesta = await request(appDePrueba()).get('/api/error-desconocido')



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


      expect(respuesta.headers['access-control-allow-origin']).toBeUndefined()
    })

    it('permite un origen que SI esta en la allowlist', async () => {
      const app = crearApp()
      const respuesta = await request(app)
        .get('/health')
        .set('Origin', 'http://localhost:5173')

      expect(respuesta.status).toBe(200)
      expect(respuesta.headers['access-control-allow-origin']).toBe('http://localhost:5173')


      expect(respuesta.headers['access-control-allow-credentials']).toBe('true')
    })
  })
})
