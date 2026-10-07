


const CONTRASENAS_COMUNES = new Set([
  '123456',
  'password',
  '123456789',
  '12345678',
  '12345',
  '1234567',
  'qwerty',
  'abc123',
  '111111',
  '123123',
  'admin',
  'letmein',
  'monkey',
  'dragon',
  'iloveyou',
  'sunshine',
  'princess',
  'football',
  'baseball',
  'welcome',
  'contrasena',
  'password1',
])


export const LONGITUD_MINIMA = 12


export const LONGITUD_MAXIMA = 128


export interface ResultadoValidacion {
  valida: boolean
  problemas: string[]
}


export function validarContrasena(contrasena: string): ResultadoValidacion {
  const problemas: string[] = []

  if (contrasena.length < LONGITUD_MINIMA) {
    problemas.push(`La contrasena tiene que tener al menos ${LONGITUD_MINIMA} caracteres`)
  }

  if (contrasena.length > LONGITUD_MAXIMA) {
    problemas.push(`La contrasena no puede superar los ${LONGITUD_MAXIMA} caracteres`)
  }

  if (CONTRASENAS_COMUNES.has(contrasena.toLowerCase())) {
    problemas.push('Esa contrasena aparece en las listas de contrasenas mas usadas')
  } else {







    const sinDigitosNiSimbolos = contrasena
      .toLowerCase()
      .replace(/[0-9!@#$%^&*(),.?":{}|<>_\-+=[\]/\\;'`~]/g, '')

    if (CONTRASENAS_COMUNES.has(sinDigitosNiSimbolos)) {
      problemas.push('Esa contrasena es una variante de una contrasena muy usada')
    }
  }

  return { valida: problemas.length === 0, problemas }
}


export function contrasenaEsValida(contrasena: string): boolean {
  return validarContrasena(contrasena).valida
}
