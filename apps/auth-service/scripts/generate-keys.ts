/**
 * Generador de llaves ES256 para firmar los access tokens.
 *
 * Por que ES256 y no RSA:
 *   - La llave privada de ES256 pesa 32 bytes. La de RSA 2048, unos 1.2 KB.
 *   - Generar un par RSA tarda cientos de milisegundos y puede fallar por
 *     el factor de aleatoriedad, lo que en un cold start de Vercel es un
 *     problema. ES256 se genera al instante.
 *   - La seguridad es equivalente (ECDSA sobre la curva P-256 contra RSA 2048).
 *
 * Como funciona la criptografia asimetrica (explicacion.md, seccion 6):
 *   - La llave PRIVADA firma los tokens. Vive solo en el servidor.
 *   - La llave PUBLICA verifica las firmas. Se publica sin riesgo en
 *     /.well-known/jwks.json, para que cualquier resource server pueda
 *     validar nuestros tokens sin llamarnos.
 *
 * El `kid` (key ID) permite rotar llaves sin downtime: se genera un par nuevo,
 * se cambia el JWT_KEY_ID, y se publican las dos llaves en el jwks.json.
 *
 * Uso:
 *   npm run keys:generate
 *
 * Copia la salida al archivo .env.
 */

import { generateKeyPairSync } from 'node:crypto'

const YEAR = new Date().getFullYear()

function generarLlavesES256() {
  // 'ec' = elliptic curve. 'prime256v1' = NIST P-256, la curva de ES256.
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  })

  return {
    // PKCS8 es el formato estándar de la llave privada.
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    // SPKI es el formato estándar de la llave publica.
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  }
}

const { privateKeyPem, publicKeyPem } = generarLlavesES256()

// El key ID identifica la llave en el header del JWT y en el jwks.json.
// Es lo que permite tener mas de una llave activa durante una rotacion.
const keyId = `key-${YEAR}-${Math.random().toString(36).slice(2, 10)}`

const linea = '='.repeat(70)

console.log(linea)
console.log('LLAVES ES256 GENERADAS')
console.log(linea)
console.log('')
console.log('1) Pegá esto en tu archivo .env:')
console.log('')
console.log(`JWT_KEY_ID=${keyId}`)
console.log(`JWT_PRIVATE_KEY="${privateKeyPem.trim()}"`)
console.log(`JWT_PUBLIC_KEY="${publicKeyPem.trim()}"`)
console.log('')
console.log('2) El valor de JWT_PUBLIC_KEY es publico por diseño: se expone')
console.log('   en /.well-known/jwks.json para que otros puedan validar')
console.log('   nuestros tokens. La privada NO se publica nunca.')
console.log('')
console.log(linea)
console.log('La llave privada nunca se sube al repositorio ni sale del servidor.')
console.log(linea)
