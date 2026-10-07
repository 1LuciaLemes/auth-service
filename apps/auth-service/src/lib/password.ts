

import { Algorithm, hash, verify } from '@node-rs/argon2'


const PARAMETROS_ARGON2 = {
  algorithm: Algorithm.Argon2id,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
  outputLen: 32,
}


export const parametrosArgon2 = PARAMETROS_ARGON2


export async function hashearContrasena(contrasena: string): Promise<string> {
  return hash(contrasena, PARAMETROS_ARGON2)
}


export async function verificarContrasena(
  hashGuardado: string,
  contrasena: string,
): Promise<boolean> {
  try {
    return await verify(hashGuardado, contrasena)
  } catch {




    return false
  }
}


let hashDeReferencia: string | null = null


export async function inicializarHashDeReferencia(): Promise<void> {


  hashDeReferencia = await hashearContrasena('valor-aleatorio-solo-para-igualar-tiempos')
}


export async function verificarContraReferencia(contrasena: string): Promise<void> {
  if (hashDeReferencia === null) {
    await inicializarHashDeReferencia()
  }




  const referencia = hashDeReferencia ?? (await hashearContrasena('respaldo'))


  await verificarContrasena(referencia, contrasena)
}


export function necesitaRehash(hashGuardado: string): boolean {


  const patron = /\$argon2id\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$/
  const encontrado = hashGuardado.match(patron)




  if (!encontrado) return true

  const memoriaGuardada = Number(encontrado[1])
  const iteracionesGuardadas = Number(encontrado[2])
  const paralelismoGuardado = Number(encontrado[3])


  return (
    memoriaGuardada < PARAMETROS_ARGON2.memoryCost ||
    iteracionesGuardadas < PARAMETROS_ARGON2.timeCost ||
    paralelismoGuardado !== PARAMETROS_ARGON2.parallelism
  )
}
