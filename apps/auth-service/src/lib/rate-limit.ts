


export interface DecisionLimite {

  permitido: boolean

  restantes: number

  segundosParaReintentar: number

  limite: number
}


export interface ReglaLimite {

  maximo: number

  ventanaMs: number
}


export interface RateLimiter {
  consumir(clave: string, ahora?: number): DecisionLimite
  limpiar(clave: string): void
  purgar(ahora?: number): number
  readonly tamano: number
}

interface EntradaVentana {

  cuenta: number

  reiniciaEn: number
}


export class MemoryRateLimiter implements RateLimiter {
  private readonly entradas = new Map<string, EntradaVentana>()

  constructor(private readonly regla: ReglaLimite) {}


  consumir(clave: string, ahora: number = Date.now()): DecisionLimite {









    if (this.regla.maximo <= 0) {
      return {
        permitido: false,
        restantes: 0,
        segundosParaReintentar: Math.max(1, Math.ceil(this.regla.ventanaMs / 1000)),
        limite: this.regla.maximo,
      }
    }

    const existente = this.entradas.get(clave)


    if (!existente || ahora >= existente.reiniciaEn) {
      this.entradas.set(clave, {
        cuenta: 1,
        reiniciaEn: ahora + this.regla.ventanaMs,
      })
      return {
        permitido: true,
        restantes: this.regla.maximo - 1,
        segundosParaReintentar: 0,
        limite: this.regla.maximo,
      }
    }

    if (existente.cuenta >= this.regla.maximo) {





      return {
        permitido: false,
        restantes: 0,
        segundosParaReintentar: Math.max(1, Math.ceil((existente.reiniciaEn - ahora) / 1000)),
        limite: this.regla.maximo,
      }
    }

    existente.cuenta += 1

    return {
      permitido: true,
      restantes: this.regla.maximo - existente.cuenta,
      segundosParaReintentar: 0,
      limite: this.regla.maximo,
    }
  }


  limpiar(clave: string): void {
    this.entradas.delete(clave)
  }


  purgar(ahora: number = Date.now()): number {
    let borradas = 0

    for (const [clave, entrada] of this.entradas) {
      if (ahora >= entrada.reiniciaEn) {
        this.entradas.delete(clave)
        borradas += 1
      }
    }

    return borradas
  }


  get tamano(): number {
    return this.entradas.size
  }
}


export class RateLimiterQueRechazaTodo implements RateLimiter {
  constructor(private readonly regla: ReglaLimite) {}

  consumir(): DecisionLimite {
    return {
      permitido: false,
      restantes: 0,
      segundosParaReintentar: 60,
      limite: this.regla.maximo,
    }
  }

  limpiar(): void {}
  purgar(): number {
    return 0
  }
  get tamano(): number {
    return 0
  }
}
