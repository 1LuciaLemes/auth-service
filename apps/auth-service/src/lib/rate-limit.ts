/**
 * Rate limiting.
 *
 * Que es: contar peticiones por una clave (normalmente una IP) en una ventana
 * de tiempo, y rechazar las que se pasan del limite.
 *
 * Por que el login y el reset de contrasena lo necesitan
 *
 * El bloqueo por intentos fallidos protege la CUENTA. El rate limiting protege
 * el SISTEMA, y son cosas distintas:
 *
 *   - El bloqueo por intentos solo ayuda si el atacante ataca una cuenta que
 *     existe. Contra un email inexistente no hay cuenta que bloquear, y se
 *     puede probar una lista de 100.000 emails sin verse limitado nunca.
 *   - Ademas, un atacante puede repartir los intentos entre cuentas y no
 *     llegar nunca a 5 en ninguna de ellas.
 *
 * En ambos casos, sin rate limiting, el atacante gana: lo que cuesta ~100 ms
 * por intento de argon2 lo pone a 10 peticiones por segundo por IP, y cada
 * intento contra un email inexistente iguala el tiempo de respuesta.
 *
 * La diferencia con el bloqueo tambien esta en donde se aplica: el bloqueo es
 * por cuenta y persiste en la base; el rate limit es por IP y vive en memoria.
 *
 * Ver explicacion.md, seccion 21.
 */

/** Resultado de consultar el limite para una clave. */
export interface DecisionLimite {
  /** Si la peticion se puede seguir. */
  permitido: boolean
  /** Peticiones que quedan en la ventana actual. */
  restantes: number
  /** Segundos hasta que se libere un hueco. Va en el header Retry-After. */
  segundosParaReintentar: number
  /** El limite configurado. Se usa para la cabecera X-RateLimit-Limit. */
  limite: number
}

/** Una regla de limite. */
export interface ReglaLimite {
  /** Peticiones permitidas dentro de la ventana. */
  maximo: number
  /** Longitud de la ventana, en milisegundos. */
  ventanaMs: number
}

/**
 * Lo que un endpoint necesita de un limitador.
 *
 * Es una interface y no la clase concreta para que los tests puedan pasar un
 * limitador falso sin tener que esperar a que se agote uno real, que es la
 * unica forma de probar de verdad que un endpoint respeta el limite.
 */
export interface RateLimiter {
  consumir(clave: string, ahora?: number): DecisionLimite
  limpiar(clave: string): void
  purgar(ahora?: number): number
  readonly tamano: number
}

interface EntradaVentana {
  /** Cuantas peticiones van dentro de la ventana actual. */
  cuenta: number
  /** Cuando termina la ventana actual. */
  reiniciaEn: number
}

/**
 * Limitador en memoria, con ventana fija.
 *
 * "Ventana fija" significa que la ventana empieza con la primera peticion y no
 * se mueve: si alguien pide 5 permisos a las 10:00:00, el contador baja a cero
 * a las 10:01:00, no un segundo antes por peticion.
 *
 * La alternativa, la ventana deslizante, mide las peticiones de los ultimos N
 * segundos y es mas exacta, pero obliga a guardar un timestamp por peticion y a
 * descartar los viejos. Con un auth server de este tamano la diferencia no se
 * nota, y la ventana fija se puede limpiar con un temporizador en vez de
 * recorrer un array en cada peticion.
 *
 * OJO CON LA LIMITACION, que es real y hay que conocer: al vivir en memoria,
 * este limitador es POR PROCESO. Con dos instancias de la misma app, cada una
 * lleva su contador y el atacante recibe el doble de lo permitido. Para un
 * despliegue con mas de una instancia hace falta el limitador compartido de
 * Redis, y que esto sea una interface es justo lo que permite cambiarlo sin
 * tocar ni un endpoint.
 */
export class MemoryRateLimiter implements RateLimiter {
  private readonly entradas = new Map<string, EntradaVentana>()

  constructor(private readonly regla: ReglaLimite) {}

  /**
   * Consulta y consume un hueco de la cuota.
   *
   * "Consume" significa que suma uno SI la peticion se permite. Un metodo
   * `allowed()` que no hiciera esto permitiria reenviar el mismo request mil
   * veces sin que el contador se enterara, y no serviria para nada.
   */
  consumir(clave: string, ahora: number = Date.now()): DecisionLimite {
    // Un limite de 0 significa "no pasa nadie", y se comprueba ANTES de tocar
    // nada. Sin esta comprobacion, la primera peticion crearia su ventana y
    // pasaria: un fallo abierto.
    //
    // Y no es hipotetico. Calcular el limite de un endpoint a partir de
    // configuracion es facil, y un `0` por un redondeo o por una division
    // equivocada significa que el endpoint se queda SIN NINGUNA proteccion,
    // en silencio. Cerrar en vez de abrir hace que el error se vea enseguida:
    // el endpoint devuelve 429 para todo y se nota en el primer test.
    if (this.regla.maximo <= 0) {
      return {
        permitido: false,
        restantes: 0,
        segundosParaReintentar: Math.max(1, Math.ceil(this.regla.ventanaMs / 1000)),
        limite: this.regla.maximo,
      }
    }

    const existente = this.entradas.get(clave)

    // Ventana nueva, o la anterior ya termino.
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
      // Agotado. Esta peticion NO se cuenta, y esa es la parte importante: si
      // se contara, cada intento seguiria empujando el reinicio de la ventana
      // hacia adelante, y un atacante que siguiera reintentando sin parar
      // jamas volveria a entrar. Es la "tormenta de reintentos": el limite se
      // vuelve permanente solo por insistencia.
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

  /**
   * Borra el contador de una clave.
   *
   * Se usa tras un login EXITOSO, para que un usuario legitimo que escribio
   * mal la contrasena tres veces no salga del limite. Sin esto, un usuario que
   * falla la contrasena cinco veces por un error de tecleo tendria que esperar
   * a que expirara la ventana, sin aviso y sin poder hacer nada.
   *
   * NO se hace tras un fallo: ahi el limite tiene que seguir contando, que es
   * exactamente lo que frena el ataque.
   */
  limpiar(clave: string): void {
    this.entradas.delete(clave)
  }

  /**
   * Borra las entradas que ya no sirven.
   *
   * Sin esto el Map crece sin limite: cada IP que toca el service deja una
   * entrada permanente, y con millones de IPs distintas el proceso se come la
   * memoria. Es la fuga clasica de usar un Map como cache sin TTL.
   */
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

  /** Cuantas claves hay ahora. Solo para tests y para logs. */
  get tamano(): number {
    return this.entradas.size
  }
}

/**
 * Limitador que rechaza siempre.
 *
 * Solo existe para tests: sirve para comprobar que un endpoint respeta un
 * limitador sin tener que agotar uno real, que con una ventana de 15 minutos
 * haria la suite interminable.
 */
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
