/**
 * Validacion de redirect URIs.
 *
 * Este archivo es la defensa contra OPEN REDIRECT, y es probablemente el
 * pedazo de codigo mas importante de todo el service.
 *
 * QUE ES UN OPEN REDIRECT Y POR QUE ES TAN GRAVE ACA
 *
 * El atacante convince al usuario de hacer clic en un link que empieza con la
 * URL de nuestro service y termina en la del atacante:
 *
 *   https://auth.miservidor.com/authorize?
 *     client_id=miapp
 *     &redirect_uri=https://sitio-malicioso.example/robo
 *     &response_type=code
 *
 * El service lo acepta, manda al usuario al sitio del atacante CON EL
 * authorization code en la URL, y ese sitio lo cambia por tokens. El usuario
 * acaba autenticado en una aplicacion que el atacante controla.
 *
 * El sentido del daño es contraintuitivo: el atacante no entra en la cuenta
 * del usuario, USA al usuario para que el codigo llegue a el. Por eso la
 * validacion tiene que ser la mas estricta del service, mas que la de las
 * contrasenas, porque un attacker puede generar combinaciones de contrasenas
 * mucho mas rapido que de redirect URIs.
 *
 * LA REGLA: COINCIDENCIA EXACTA DE CADENA
 *
 * Un redirect URI registrado como
 *
 *   https://app.example.com/callback
 *
 * SOLO acepta ese string exacto. No acepta:
 *
 *   https://app.example.com/callback/extra    (path distinto)
 *   https://app.example.com/callback?next=/x (query distinto)
 *   https://APP.example.com/callback          (distinto mayus/minus, distinta
 *                                              cadena)
 *   https://app.example.com.evil.com/callback (otro dominio entero)
 *   https://app.example.com/callback.evil.com (otro dominio, del todo)
 *
 * Ni siquiera un subdominio. El error clasico es implementar la comparacion con
 * startsWith, que suena conservador y no lo es: el atacante elige el resto de
 * su URL, asi que si puede hacer que el prefijo coincida, elige `evil.com`
 * como dominio. Ver explicacion.md, seccion 17.
 *
 * ESTE MODULO ES CODIGO PURO A PROPOSITO: no toca base de datos ni entorno, solo
 * strings. Eso lo hace testeable de forma exhaustiva, que es lo que necesita un
 * archivo cuya falla sea un robo de sesion.
 */

import { errorDeValidacion } from '../../lib/errors.js'

/** Un redirect URI ya validado en el registro. */
export type RedirectUriValidada = string

/**
 * Por que NO se usa `new URL()` para comparar.
 *
 * `new URL()` normaliza: `https://app.com` y `https://app.com/` dan el mismo
 * objeto, y tambien normaliza mayusculas del host, eliminacion de puertos
 * por defecto, y porcentajes de codificacion. Para COMPARAR dos URLs eso
 * estaria bien y hasta conviene. El problema es que la regla de OAuth pide
 * comparar la CADENA, y si se normaliza, un redirect URI registrado como
 * `https://app.com/callback` tambien aceptaria `https://app.com:443/callback`,
 * que no es la misma cadena y no estaba registrado.
 *
 * Decidir si se normaliza es una eleccion de diseno, no un detalle: la
 * posicion de la spec (seccion 3.1.2.3) es que la comparacion es de cadenas y
 * que el servidor puede normalizar, pero si normaliza, tiene que hacerlo al
 * REGISTRAR, no al comparar. Aca se elige la opcion simple y segura: la
 * comparacion es de cadenas y punto. Si dos strings se ven iguales en un
 * cliente, tienen que ser el mismo string.
 */

/** Errores que puede dar la validacion de un redirect URI. */
export type MotivoRechazoRedirectUri =
  | 'vacia'
  | 'no_es_url'
  | 'protocolo_no_permitido'
  | 'fragmento_no_permitido'
  | 'caracteres_invalidos'
  | 'larga_demasiado'

/** Resultado de validar un redirect URI. */
export type ResultadoValidacionRedirectUri =
  | { valido: true; uri: string }
  | { valido: false; motivo: MotivoRechazoRedirectUri }

/**
 * Protocolos permitidos.
 *
 * `http:` solo se acepta para localhost y para IPs privadas, y la razon es que
 * las apps de escritorio y los servidores de desarrollo corren en
 * `http://localhost`. Aceptar `http:` en general seria permitir que el
 * authorization code viaje en claro por la red.
 *
 * `http://localhost` tiene una excepcion en la RFC 8252 (OAuth 2.0 for Native
 * Apps), que reconoce que el loopback es de confianza local. Ojo: el
 * `localhost` de una app movil no es el localhost de la PC del usuario, asi que
 * la RFC dice que se use el loopback address literal. Aca se acepta el
 * hostname y las IPs de loopback, que cubre el caso de desarrollo real.
 */
const PROTOCOLOS_PERMITIDOS = new Set(['https:', 'http:'])

/**
 * Longitud maxima. El limite de una URL en los navegadores anda por los 2000
 * caracteres, y en general los servidores HTTP rechazan por arriba de 8000. Un
 * limite propio evita depender de ese comportamiento.
 */
const LONGITUD_MAXIMA = 2000

/**
 * Caracteres que se rechazan aunque la URL sea valida.
 *
 * El caso importante es el salto de linea y el espacio, porque permiten
 * inyectar cabeceras HTTP: un redirect URI con `\r\n` seguido de
 * `Set-Cookie: ...` es un header injection clasico. `new URL()` los convierte
 * a %0D%0A y no lo detecta, asi que se comprueba ANTES de parsear.
 */
const CARACTERES_PELIGROSOS = /[\s\u0000-\u001F\u007F]/

/**
 * Determina si un host es de loopback.
 *
 * Se aceptan tanto el hostname `localhost` como las IPs literales, porque las
 * herramientas de desarrollo usan las dos: Vite abre en `localhost`, y un
 * contenedor propio suele abrir en `127.0.0.1`.
 *
 * OJO con `::1`: es IPv6, y en una URL va entre corchetes. Por eso se
 * normaliza sacando los corchetes.
 */
function esLoopback(host: string): boolean {
  const hostNormalizado = host.toLowerCase().replace(/^\[|\]$/g, '')

  return (
    hostNormalizado === 'localhost' ||
    hostNormalizado === '127.0.0.1' ||
    hostNormalizado === '::1' ||
    // 127.0.0.0/8 es todo el rango de loopback en IPv4, no solo la primera
    // direccion. Un atacante en la misma red no puede capitalizar esto
    // porque igual tiene que tener el control de esa IP.
    hostNormalizado.startsWith('127.')
  )
}

/**
 * Valida el FORMATO de un redirect URI, sin mirar si esta registrado.
 *
 * Esto es la primera linea de defensa, y se aplica al REGISTRAR: si un URI con
 * formato invalido se acepta en la base, despues no hay forma de saber si era
 * un error de tipeo o un intento de ataque.
 *
 * Devuelve un resultado en vez de tirar, para que el endpoint de registro pueda
 * juntar los problemas de todos los URIs y mostrarlos juntos, en vez de
 * fallar por el primero.
 */
export function validarFormatoRedirectUri(uri: string): ResultadoValidacionRedirectUri {
  if (uri.length === 0) {
    return { valido: false, motivo: 'vacia' }
  }

  if (uri.length > LONGITUD_MAXIMA) {
    return { valido: false, motivo: 'larga_demasiado' }
  }

  // Se comprueba antes de parsear. `new URL()` no ayuda: normaliza el salto de
  // linea a %0A y devuelve una URL que parece valida.
  if (CARACTERES_PELIGROSOS.test(uri)) {
    return { valido: false, motivo: 'caracteres_invalidos' }
  }

  let url: URL
  try {
    url = new URL(uri)
  } catch {
    // No es una URL absoluta. En OAuth el redirect URI tiene que ser ABSOLUTA:
    // relativa no tiene sentido porque el navegador la resolveria contra la
    // pagina del usuario, no contra el service.
    return { valido: false, motivo: 'no_es_url' }
  }

  if (!PROTOCOLOS_PERMITIDOS.has(url.protocol)) {
    return { valido: false, motivo: 'protocolo_no_permitido' }
  }

  // `http:` solo para loopback. Cualquier otro host con http significa que el
  // authorization code va a viajar sin cifrar por la red.
  if (url.protocol === 'http:' && !esLoopback(url.hostname)) {
    return { valido: false, motivo: 'protocolo_no_permitido' }
  }

  // OAuth 2.0 (RFC 6749, seccion 3.1.2) prohibe el fragmento en el redirect URI.
  // La razon tecnica es que el fragmento no se envia al servidor: si el
  // authorization code fuera a estar en el fragmento, jamas llegaria al
  // endpoint, y el flujo no tendria sentido.
  if (url.hash !== '') {
    return { valido: false, motivo: 'fragmento_no_permitido' }
  }

  // NO se comprueba que el host este vacio, y vale la pena decir por que, porque
  // parece un chequeo que faltaria: el parser de WHATWG tira ERR_INVALID_URL
  // para `https://` sin host, `https://:8080/cb` y `https://?x=1`, y todo eso
  // ya cae en el `no_es_url` de mas arriba. La unica forma de llegar con host
  // vacio es un esquema no especial como `file:`, y ese ya lo rechaza el chequeo
  // de protocolo. La comprobacion seria inalcanzable.
  //
  // Un chequeo muerto en un modulo de seguridad es peor que no tenerlo: sugiere
  // una proteccion que en realidad no existe, y alguien podria "arreglar" el
  // orden de las validaciones creyendo que esa linea sostiene algo.
  //
  // Lo que si es cierto, y por eso no hace falta un chequeo de "un solo
  // label": `https:///callback` NO es una URL sin host. El parser la interpreta
  // como host `callback` con path `/`, o sea `https://callback/`. Es una URL
  // valida y de un solo label, que es raro pero no peligroso: para que sirva
  // tiene que estar REGISTRADA, y el registro exige coincidencia exacta.

  return { valido: true, uri }
}

/**
 * Compara un redirect URI recibido contra los registrados.
 *
 * COINCIDENCIA EXACTA. Esta es la funcion que evita el open redirect, y por
 * eso es tan corta: no hay logica que pueda tener un error de borde.
 *
 * Por que no se normaliza antes de comparar: si se normalizara, un URI
 * registrado como `https://app.com/callback` tambien aceptaria
 * `https://app.com:443/callback` o `https://APP.com/callback`, que no son el
 * mismo string. La spec pide comparar cadenas, y una cadena es una cadena.
 * Ver el comentario de la cabecera del archivo.
 */
export function redirectUriPermitido(
  uriRecibida: string,
  urisRegistradas: readonly string[],
): boolean {
  return urisRegistradas.includes(uriRecibida)
}

/**
 * Valida una lista de redirect URIs para el registro de un cliente.
 *
 * Todas tienen que tener formato valido. Devuelve error de validacion con el
 * detalle de CUAL fallo, porque un URI mal escrito casi siempre es un error de
 * tipeo y el developer tiene que saber cual de los veinte es.
 *
 * @throws AppError de validacion si alguna falla o si hay duplicados.
 */
export function validarListaDeRedirectUris(uris: string[]): RedirectUriValidada[] {
  if (uris.length === 0) {
    throw errorDeValidacion('Hay que registrar al menos un redirect URI')
  }

  // Tope de 10. Es un limite de diseno, no tecnico: un cliente con 30 URIs
  // casi siempre tiene un problema de diseno (un multi-tenant que deberia
  // resolverlo distinto), y permitirlo haria mas lento el matching.
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

  // Duplicados: se RECHAZAN en vez de deduplicar en silencio.
  //
  // Podria deduplicarse sin avisar, y el resultado funcional seria el mismo.
  // Se elige fallar porque un duplicado casi siempre es un copypaste, y
  // deduplicar en silencio deja una configuracion que el developer cree
  // completa y en realidad no lo esta: si registra 5 URIs y dos son la misma,
  // espera 5 destinos validos y tiene 4. Es mejor que el error lo diga.
  const unicas = [...new Set(validas)]
  if (unicas.length !== validas.length) {
    const repetidos = unicas.filter((uri) => validas.filter((v) => v === uri).length > 1)
    errores.push(`Hay redirect URIs duplicados: ${repetidos.join(', ')}`)
  }

  if (errores.length > 0) {
    throw errorDeValidacion('Redirect URIs invalidos', { problemas: errores })
  }

  // El Set de arriba no es decorativo aunque el error ya haya tirado: garantiza
  // que lo que se devuelve no tiene repetidos, sin importar que se agregue una
  // validacion nueva en el futuro que cambie el flujo.
  return unicas
}

/** Traduce un motivo a un mensaje que un developer pueda arreglar. */
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
