

import { errorDeValidacion } from '../../lib/errors.js'


export type RedirectUriValidada = string




export type MotivoRechazoRedirectUri =
  | 'vacia'
  | 'no_es_url'
  | 'protocolo_no_permitido'
  | 'fragmento_no_permitido'
  | 'caracteres_invalidos'
  | 'larga_demasiado'


export type ResultadoValidacionRedirectUri =
  | { valido: true; uri: string }
  | { valido: false; motivo: MotivoRechazoRedirectUri }


const PROTOCOLOS_PERMITIDOS = new Set(['https:', 'http:'])


const LONGITUD_MAXIMA = 2000


const CARACTERES_PELIGROSOS = /[\s\u0000-\u001F\u007F]/


function esLoopback(host: string): boolean {
  const hostNormalizado = host.toLowerCase().replace(/^\[|\]$/g, '')

  return (
    hostNormalizado === 'localhost' ||
    hostNormalizado === '127.0.0.1' ||
    hostNormalizado === '::1' ||



    hostNormalizado.startsWith('127.')
  )
}


export function validarFormatoRedirectUri(uri: string): ResultadoValidacionRedirectUri {
  if (uri.length === 0) {
    return { valido: false, motivo: 'vacia' }
  }

  if (uri.length > LONGITUD_MAXIMA) {
    return { valido: false, motivo: 'larga_demasiado' }
  }



  if (CARACTERES_PELIGROSOS.test(uri)) {
    return { valido: false, motivo: 'caracteres_invalidos' }
  }

  let url: URL
  try {
    url = new URL(uri)
  } catch {



    return { valido: false, motivo: 'no_es_url' }
  }

  if (!PROTOCOLOS_PERMITIDOS.has(url.protocol)) {
    return { valido: false, motivo: 'protocolo_no_permitido' }
  }



  if (url.protocol === 'http:' && !esLoopback(url.hostname)) {
    return { valido: false, motivo: 'protocolo_no_permitido' }
  }





  if (url.hash !== '') {
    return { valido: false, motivo: 'fragmento_no_permitido' }
  }


















  return { valido: true, uri }
}


export function redirectUriPermitido(
  uriRecibida: string,
  urisRegistradas: readonly string[],
): boolean {
  return urisRegistradas.includes(uriRecibida)
}


export function validarListaDeRedirectUris(uris: string[]): RedirectUriValidada[] {
  if (uris.length === 0) {
    throw errorDeValidacion('Hay que registrar al menos un redirect URI')
  }




  if (uris.length > 10) {
    throw errorDeValidacion('No se pueden registrar mas de 10 redirect URIs')
  }

  const errores: string[] = []
  const validas: string[] = []

  uris.forEach((uri, indice) => {
    const resultado = validarFormatoRedirectUri(uri)

    if (resultado.valido) {
      validas.push(resultado.uri)
      return
    }

    errores.push(`URI ${indice + 1} (${uri || 'vacio'}): ${explicarMotivo(resultado.motivo)}`)
  })








  const unicas = [...new Set(validas)]
  if (unicas.length !== validas.length) {
    const repetidos = unicas.filter((uri) => validas.filter((v) => v === uri).length > 1)
    errores.push(`Hay redirect URIs duplicados: ${repetidos.join(', ')}`)
  }

  if (errores.length > 0) {
    throw errorDeValidacion('Redirect URIs invalidos', { problemas: errores })
  }




  return unicas
}


function explicarMotivo(motivo: MotivoRechazoRedirectUri): string {
  switch (motivo) {
    case 'vacia':
      return 'esta vacio'
    case 'no_es_url':
      return 'tiene que ser una URL absoluta, con esquema (por ejemplo https://)'
    case 'protocolo_no_permitido':
      return 'solo se permite https, o http unicamente para localhost'
    case 'fragmento_no_permitido':
      return 'no puede tener un fragmento (la parte despues del #)'
    case 'caracteres_invalidos':
      return 'tiene espacios, saltos de linea o caracteres de control'
    case 'larga_demasiado':
      return `es mas larga de ${LONGITUD_MAXIMA} caracteres`
  }
}
