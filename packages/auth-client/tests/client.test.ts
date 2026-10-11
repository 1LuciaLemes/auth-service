import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, crearClienteDeAuth } from '../src/index.js'

let ultimaPeticion: { url: string; init?: RequestInit } | undefined

function mockearFetch(estado: number, cuerpo: unknown, headers?: Record<string, string>) {
  const fetchImpl = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
    ultimaPeticion = { url: String(_url), init }
    return new Response(JSON.stringify(cuerpo), {
      status: estado,
      headers: { 'content-type': 'application/json', ...headers },
    })
  })

  vi.stubGlobal('fetch', fetchImpl)
  return fetchImpl
}

function construirCliente() {
  return crearClienteDeAuth({ baseUrl: 'http://localhost:3000' })
}

afterEach(() => {
  ultimaPeticion = undefined
  vi.unstubAllGlobals()
})

describe('cliente de auth', () => {
  it('registra enviando POST con el cuerpo y las cabeceras correctas', async () => {
    mockearFetch(201, { userId: 'u-1', email: 'nueva@example.com' })

    const resultado = await construirCliente().registrar({
      email: 'nueva@example.com',
      contrasena: 'UnaContrasenaLarga1!',
      displayName: 'Nueva',
    })

    expect(resultado).toEqual({ userId: 'u-1', email: 'nueva@example.com' })
    expect(ultimaPeticion?.url).toBe('http://localhost:3000/api/v1/auth/register')
    expect(ultimaPeticion?.init?.method).toBe('POST')
    expect(JSON.parse(String(ultimaPeticion?.init?.body))).toEqual({
      email: 'nueva@example.com',
      contrasena: 'UnaContrasenaLarga1!',
      displayName: 'Nueva',
    })
  })

  it('inicia sesion y devuelve el estado de verificacion', async () => {
    mockearFetch(200, { userId: 'u-1', email: 'log@example.com', emailVerificado: true })

    const resultado = await construirCliente().iniciarSesion({
      email: 'log@example.com',
      contrasena: 'UnaContrasenaLarga1!',
    })

    expect(resultado).toEqual({ userId: 'u-1', email: 'log@example.com', emailVerificado: true })
  })

  it('verifica email y completa el reset con la misma forma de respuesta', async () => {
    mockearFetch(200, { ok: true })

    const cliente = construirCliente()

    expect(await cliente.verificarEmail({ token: 'abc' })).toEqual({ ok: true })
    expect(await cliente.completarResetDeContrasena({
      token: 'abc',
      nuevaContrasena: 'OtraContrasenaLarga1!',
    })).toEqual({ ok: true })
  })

  it('lanza ApiError con el codigo y message del servidor', async () => {
    mockearFetch(401, { error: 'invalid_credentials', message: 'Credenciales invalidas.' })

    const error = await construirCliente()
      .iniciarSesion({ email: 'bad@example.com', contrasena: 'mala' })
      .then(() => null)
      .catch((e) => e)

    expect(error).toBeInstanceOf(ApiError)
    expect(error.code).toBe('invalid_credentials')
    expect(error.status).toBe(401)
    expect(error.message).toBe('Credenciales invalidas.')
  })

  it('expone retryAfter cuando el 429 trae Retry-After', async () => {
    mockearFetch(429, { error: 'rate_limited', message: 'Demasiados intentos.' }, { 'retry-after': '32' })

    const error = await construirCliente()
      .registrar({ email: 'mucho@example.com', contrasena: 'UnaContrasenaLarga1!' })
      .then(() => null)
      .catch((e) => e)

    expect(error).toBeInstanceOf(ApiError)
    expect(error.code).toBe('rate_limited')
    expect(error.retryAfter).toBe(32)
  })

  it('devuelve un error generico si el cuerpo del error no es JSON', async () => {
    const fetchImpl = vi.fn(async () => new Response('no es json', { status: 502 }))
    vi.stubGlobal('fetch', fetchImpl)

    const error = await construirCliente()
      .obtenerJwks()
      .then(() => null)
      .catch((e) => e)

    expect(error).toBeInstanceOf(ApiError)
    expect(error.status).toBe(502)
    expect(error.code).toBe('server_error')
  })

  it('pide el jwks con GET y sin cuerpo', async () => {
    mockearFetch(200, {
      keys: [{ kid: 'k-1', alg: 'ES256', use: 'sig', kty: 'EC' }],
    })

    const jwks = await construirCliente().obtenerJwks()

    expect(jwks.keys).toHaveLength(1)
    expect(jwks.keys[0]?.kid).toBe('k-1')
    expect(ultimaPeticion?.url).toBe('http://localhost:3000/api/.well-known/jwks.json')
    expect(ultimaPeticion?.init?.method).toBe('GET')
    expect(ultimaPeticion?.init?.body).toBeUndefined()
  })

  it('normaliza la baseUrl sin barra final', async () => {
    mockearFetch(200, { keys: [] })

    await crearClienteDeAuth({ baseUrl: 'http://localhost:3000/' }).obtenerJwks()

    expect(ultimaPeticion?.url).toBe('http://localhost:3000/api/.well-known/jwks.json')
  })

  it('permite inyectar un fetch propio', async () => {
    const fetchPropio = vi.fn(async () => new Response(JSON.stringify({ keys: [] }), { status: 200 }))

    const cliente = crearClienteDeAuth({ baseUrl: 'http://localhost:9999', fetch: fetchPropio })
    await cliente.obtenerJwks()

    expect(fetchPropio).toHaveBeenCalledTimes(1)
  })

  it('propaga los errores de red tal cual', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new TypeError('Failed to fetch')
    }))

    const error = await construirCliente()
      .obtenerJwks()
      .then(() => null)
      .catch((e) => e)

    expect(error).toBeInstanceOf(TypeError)
  })
})