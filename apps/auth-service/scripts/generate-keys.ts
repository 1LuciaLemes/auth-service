

import { generateKeyPairSync } from 'node:crypto'

const YEAR = new Date().getFullYear()

function generarLlavesES256() {

  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  })

  return {

    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),

    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  }
}

const { privateKeyPem, publicKeyPem } = generarLlavesES256()



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
