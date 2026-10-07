# auth-service

Authorization server reutilizable, del tipo OAuth 2.0 / OpenID Connect, hecho desde cero.

El usuario se autentica una vez contra este service y recibe un token. Las
aplicaciones verifican ese token con la llave publica, sin ver nunca la
contrasena ni consultar la base de datos.

- Login con Argon2id y politica de contrasenas
- Cuentas bloqueables por intentos fallidos
- JWT firmados con ES256, con `kid` para rotar la llave sin downtime
- JWKS en `/.well-known/jwks.json`
- One-time tokens para verificar email y reset de contrasena, siempre guardados
  como hash
- Validacion de redirect URI contra open redirect
- Rate limiting por IP

## Stack

TypeScript (ESM) sobre Node.js 20+, Express 4, PostgreSQL 16 con Drizzle ORM,
Zod, `jose`, Pino y Vitest. Monorepo con npm workspaces.

## Requisitos

Node.js 20 o superior y PostgreSQL 16. Docker es opcional, pero es la via
facil de levantar la base de datos.

## Uso en local

```bash
npm install
cp .env.example .env
```

Generar el par de llaves para firmar los JWT e imprimirlo para pegar en `.env`:

```bash
npm run keys:generate --workspace=@auth/service
```

Levantar la base de datos y aplicar las migraciones:

```bash
docker compose up -d
npm run db:migrate
```

Comprobar que todo esta bien:

```bash
npm run typecheck
npm test
```

## Scripts

Se ejecutan desde la raiz del monorepo.

| Script | Que hace |
| --- | --- |
| `npm run typecheck` | Typecheck sin emitir archivos |
| `npm run test` | Corre los tests de todos los workspaces |
| `npm run build` | Compila TypeScript |
| `npm run db:migrate` | Aplica las migraciones pendientes |
| `npm run db:generate` | Genera una migracion a partir del schema |
| `npm run db:studio` | Abre Drizzle Studio para ver la base |
| `npm run keys:generate --workspace=@auth/service` | Genera el par de llaves ES256 |

`npm run dev` y `npm start` necesitan `src/server.ts`, que se escribira mas
adelante: por ahora no levantan nada.

## Estructura

```
auth-service/
|-- apps/
|   `-- auth-service/
|       |-- src/
|       |   |-- app.ts          assembly de Express, NO hace listen()
|       |   |-- config/         carga y validacion de entorno con Zod
|       |   |-- db/             schema Drizzle y migraciones
|       |   |-- lib/            crypto, jwt, contrasenas, errores, logger
|       |   |-- middleware/     contexto de request, validacion, errores
|       |   `-- modules/
|       |       |-- auth/       registro, login, bloqueo, puertos
|       |       |-- clients/    validacion de redirect URI
|       |       `-- users/      one-time tokens, reset de contrasena
|       |-- scripts/           generate-keys, check-encoding
|       `-- tests/
|           |-- unit/
|           `-- integration/
|-- packages/
|   `-- auth-client/            SDK para consumir el service
|-- .env.example
`-- docker-compose.yml
```

`app.ts` devuelve la app y no la levanta. Es a proposito: los tests la importan
y le hacen requests con supertest, sin abrir un puerto real.

## Base de datos

Ocho tablas: `users`, `identities`, `clients`, `auth_codes`, `refresh_tokens`,
`sessions`, `one_time_tokens` y `audit_events`.

En desarrollo con Docker, en produccion con Neon. Solo cambia el valor de
`DATABASE_URL`, no el codigo.

## Tests

267 tests en 13 archivos, todos sin base de datos: los repositorios son
interfaces y cada test usa sus propios fakes.

`scripts/check-encoding.ps1` es una comprobacion propia del proyecto. Falla si
aparece un caracter fuera del rango latino en los fuentes, que es el sintoma de
un archivo guardado con la codificacion equivocada:

```bash
cd apps/auth-service
.\scripts\check-encoding.ps1
```

## Notas

- Los secretos van en `.env`, que esta en `.gitignore`. En el repo solo esta
  `.env.example`, con los nombres y valores de ejemplo.
