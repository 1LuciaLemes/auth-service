export { ApiError, crearErrorDesdeRespuesta } from './errors.js'
export { crearClienteDeAuth } from './client.js'
export type { ClienteDeAuth, OpcionesDelCliente } from './client.js'
export type {
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

export const SDK_NAME = '@auth/client'

export const SDK_VERSION = '1.0.0'