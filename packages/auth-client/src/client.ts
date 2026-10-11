import { crearErrorDesdeRespuesta } from './errors.js'
import type {
  ClaveJwks,
  DatoCompletarReset,
  DatoLogin,
  DatoRegistro,
  DatoSolicitudReset,
  DatoVerificacionEmail,
  Jwks,
  ResultadoCompletarReset,
  ResultadoLogin,
  ResultadoRegistro,
  ResultadoSolicitudReset,
  ResultadoVerificacionEmail,
} from './types.js'

export interface OpcionesDelCliente {
  baseUrl: string
  fetch?: typeof fetch
}

interface OpcionesDePeticion {
  metodo?: 'GET' | 'POST'
}

async function pedirJson<T>(
  fetchImpl: typeof fetch,
  baseUrl: string,
  ruta: string,
  cuerpo?: unknown,
  opciones: OpcionesDePeticion = {},
): Promise<T> {
  const respuesta = await fetchImpl(`${baseUrl}${ruta}`, {
    method: opciones.metodo ?? (cuerpo === undefined ? 'GET' : 'POST'),
    headers: { 'content-type': 'application/json' },
    body: cuerpo === undefined ? undefined : JSON.stringify(cuerpo),
  })

  if (!respuesta.ok) {
    throw await crearErrorDesdeRespuesta(respuesta)
  }

  return (await respuesta.json()) as T
}

export interface ClienteDeAuth {
  registrar(datos: DatoRegistro): Promise<ResultadoRegistro>
  verificarEmail(datos: DatoVerificacionEmail): Promise<ResultadoVerificacionEmail>
  iniciarSesion(datos: DatoLogin): Promise<ResultadoLogin>
  solicitarResetDeContrasena(datos: DatoSolicitudReset): Promise<ResultadoSolicitudReset>
  completarResetDeContrasena(datos: DatoCompletarReset): Promise<ResultadoCompletarReset>
  obtenerJwks(): Promise<Jwks>
  obtenerClavesJwks(): Promise<ClaveJwks[]>
}

export function crearClienteDeAuth(opciones: OpcionesDelCliente): ClienteDeAuth {
  const baseUrl = opciones.baseUrl.replace(/\/+$/, '')
  const fetchImpl = opciones.fetch ?? fetch

  return {
    registrar: (datos) => pedirJson(fetchImpl, baseUrl, '/api/v1/auth/register', datos),
    verificarEmail: (datos) => pedirJson(fetchImpl, baseUrl, '/api/v1/auth/verify-email', datos),
    iniciarSesion: (datos) => pedirJson(fetchImpl, baseUrl, '/api/v1/auth/login', datos),
    solicitarResetDeContrasena: (datos) =>
      pedirJson(fetchImpl, baseUrl, '/api/v1/auth/password-reset/request', datos),
    completarResetDeContrasena: (datos) =>
      pedirJson(fetchImpl, baseUrl, '/api/v1/auth/password-reset/confirm', datos),
    obtenerJwks: () => pedirJson<Jwks>(fetchImpl, baseUrl, '/api/.well-known/jwks.json'),
    obtenerClavesJwks: async () => (await pedirJson<Jwks>(fetchImpl, baseUrl, '/api/.well-known/jwks.json')).keys,
  }
}