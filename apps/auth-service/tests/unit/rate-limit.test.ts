

import { describe, expect, it } from 'vitest'
import { MemoryRateLimiter, RateLimiterQueRechazaTodo } from '../../src/lib/rate-limit.js'

const HORA = 1_700_000_000_000
const MINUTO = 60_000


const REGLA = { maximo: 5, ventanaMs: MINUTO }

describe('MemoryRateLimiter', () => {
  describe('dentro del limite', () => {
    it('permite las primeras peticiones y cuenta hacia atras', () => {
      const limiter = new MemoryRateLimiter(REGLA)

      expect(limiter.consumir('1.2.3.4', HORA).restantes).toBe(4)
      expect(limiter.consumir('1.2.3.4', HORA).restantes).toBe(3)
      expect(limiter.consumir('1.2.3.4', HORA).restantes).toBe(2)
    })

    it('la quinta todavia se permite', () => {
      const limiter = new MemoryRateLimiter(REGLA)

      for (let i = 0; i < 4; i += 1) limiter.consumir('1.2.3.4', HORA)
      const quinta = limiter.consumir('1.2.3.4', HORA)



      expect(quinta.permitido).toBe(true)
      expect(quinta.restantes).toBe(0)
    })

    it('la sexta se rechaza', () => {
      const limiter = new MemoryRateLimiter(REGLA)

      for (let i = 0; i < 5; i += 1) limiter.consumir('1.2.3.4', HORA)
      const sexta = limiter.consumir('1.2.3.4', HORA)

      expect(sexta.permitido).toBe(false)
      expect(sexta.restantes).toBe(0)
    })

    it('devuelve cuantos segundos faltan, en un numero que un header pueda llevar', () => {
      const limiter = new MemoryRateLimiter(REGLA)
      for (let i = 0; i < 5; i += 1) limiter.consumir('1.2.3.4', HORA)




      const decision = limiter.consumir('1.2.3.4', HORA + 30_000)

      expect(decision.segundosParaReintentar).toBe(30)
      expect(Number.isInteger(decision.segundosParaReintentar)).toBe(true)
    })

    it('nunca devuelve 0 segundos de espera, porque el header seria inutil', () => {
      const limiter = new MemoryRateLimiter(REGLA)
      for (let i = 0; i < 5; i += 1) limiter.consumir('1.2.3.4', HORA)



      const decision = limiter.consumir('1.2.3.4', HORA + MINUTO - 1)

      expect(decision.segundosParaReintentar).toBeGreaterThanOrEqual(1)
    })
  })

  describe('ventana fija', () => {
    it('la ventana no se renueva con cada peticion', () => {
      const limiter = new MemoryRateLimiter(REGLA)

      for (let i = 0; i < 5; i += 1) {
        limiter.consumir('1.2.3.4', HORA + i * 1000)
      }




      expect(limiter.consumir('1.2.3.4', HORA + 5000).permitido).toBe(false)
    })

    it('al pasar la ventana se puede volver a entrar', () => {
      const limiter = new MemoryRateLimiter(REGLA)
      for (let i = 0; i < 5; i += 1) limiter.consumir('1.2.3.4', HORA)

      expect(limiter.consumir('1.2.3.4', HORA + MINUTO).permitido).toBe(true)
    })

    it('la ventana arranca con la PRIMERA peticion, no con el minuto redondo', () => {



      const limiter = new MemoryRateLimiter(REGLA)

      limiter.consumir('1.2.3.4', HORA + 37_000)
      for (let i = 0; i < 4; i += 1) limiter.consumir('1.2.3.4', HORA + 37_000)

      expect(limiter.consumir('1.2.3.4', HORA + 37_000 + MINUTO).permitido).toBe(true)
    })
  })

  describe('la tormenta de reintentos', () => {
    it('rechazar NO cuenta como peticion consumida', () => {



      const limiter = new MemoryRateLimiter(REGLA)
      for (let i = 0; i < 5; i += 1) limiter.consumir('1.2.3.4', HORA)


      for (let i = 0; i < 100; i += 1) {
        expect(limiter.consumir('1.2.3.4', HORA + 1000).permitido).toBe(false)
      }




      expect(limiter.consumir('1.2.3.4', HORA + MINUTO).permitido).toBe(true)
    })
  })

  describe('aislamiento por clave', () => {
    it('las claves distintas tienen contadores independientes', () => {
      const limiter = new MemoryRateLimiter(REGLA)

      for (let i = 0; i < 5; i += 1) limiter.consumir('atacante', HORA)



      expect(limiter.consumir('atacante', HORA).permitido).toBe(false)
      expect(limiter.consumir('usuario-legitimo', HORA).permitido).toBe(true)
    })

    it('el limite es por IP, no global', () => {
      const limiter = new MemoryRateLimiter(REGLA)

      for (let clave = 0; clave < 5; clave += 1) {
        for (let i = 0; i < 5; i += 1) limiter.consumir(`ip-${clave}`, HORA)
      }




      expect(limiter.consumir('ip-4', HORA).permitido).toBe(false)
      expect(limiter.consumir('ip-nuevo', HORA).permitido).toBe(true)
    })
  })

  describe('limpiar', () => {
    it('un login exitoso resetea el contador', () => {



      const limiter = new MemoryRateLimiter(REGLA)
      for (let i = 0; i < 5; i += 1) limiter.consumir('1.2.3.4', HORA)
      expect(limiter.consumir('1.2.3.4', HORA).permitido).toBe(false)

      limiter.limpiar('1.2.3.4')

      expect(limiter.consumir('1.2.3.4', HORA).permitido).toBe(true)
    })

    it('limpiar una clave que no existe no hace nada', () => {
      const limiter = new MemoryRateLimiter(REGLA)

      expect(() => limiter.limpiar('nunca-vista')).not.toThrow()
      expect(limiter.tamano).toBe(0)
    })
  })

  describe('purgar', () => {
    it('borra las ventanas que ya caducaron', () => {
      const limiter = new MemoryRateLimiter(REGLA)
      limiter.consumir('vieja', HORA)
      limiter.consumir('otra-vieja', HORA)
      limiter.consumir('nueva', HORA + MINUTO)




      expect(limiter.purgar(HORA + MINUTO)).toBe(2)
      expect(limiter.tamano).toBe(1)
    })

    it('no borra nada si ninguna ventana caduco', () => {
      const limiter = new MemoryRateLimiter(REGLA)
      limiter.consumir('a', HORA)

      expect(limiter.purgar(HORA + 1000)).toBe(0)
      expect(limiter.tamano).toBe(1)
    })
  })

  describe('limites que nunca dejan pasar a nadie', () => {
    it('con maximo 0 no pasa ninguna peticion, ni la primera', () => {





      const limiter = new MemoryRateLimiter({ maximo: 0, ventanaMs: MINUTO })

      expect(limiter.consumir('1.2.3.4', HORA).permitido).toBe(false)
    })

    it('con maximo 1 solo pasa la primera', () => {
      const limiter = new MemoryRateLimiter({ maximo: 1, ventanaMs: MINUTO })

      expect(limiter.consumir('1.2.3.4', HORA).permitido).toBe(true)
      expect(limiter.consumir('1.2.3.4', HORA).permitido).toBe(false)
    })
  })

  describe('el limitador falso de tests', () => {
    it('rechaza siempre, sin necesidad de agotar nada', () => {
      const limiter = new RateLimiterQueRechazaTodo(REGLA)




      const decision = limiter.consumir('1.2.3.4', HORA)

      expect(decision.permitido).toBe(false)
      expect(decision.segundosParaReintentar).toBe(60)
      expect(decision.limite).toBe(REGLA.maximo)
    })
  })
})
