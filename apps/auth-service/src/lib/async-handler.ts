import type { NextFunction, Request, RequestHandler, Response } from 'express'

export function envolverAsync<Req extends Request = Request>(
  manejador: (req: Req, res: Response, next: NextFunction) => Promise<void> | void,
): RequestHandler {
  return (request, response, next) => {
    Promise.resolve(manejador(request as Req, response, next)).catch(next)
  }
}