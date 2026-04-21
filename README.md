# Rayuela backend

## Description

Backend para el framework Rayuela

## Installation
Se puede utilizar cualquier version de node LTS, 16,18 o 20.
Es recomendable utilizar node 20, puedes ejecutar `nvm use 20` o bien `nvm use 20.12.1` - la version que estoy utilizando al iniciar el proyecto -
```bash
$ npm install
```

## Running the app

1. **Start Docker Services** (MongoDB & Garage):
   ```bash
   $ docker-compose up -d
   ```

2. **Initialize Garage** (First time only):
   ```bash
   $ bash ../init-garage.sh
   ```

3. **Start Backend**:
   ```bash
   # watch mode
   $ npm run start:dev
   ```

## Google auth setup

Para habilitar el login y registro con Google, configurar `GOOGLE_CLIENT_ID` con el Client ID Web generado en Google Cloud en `.env` or `.env.development`.

## Test

```bash
# unit tests
$ npm run test

# e2e tests
$ npm run test:e2e

# test coverage
$ npm run test:cov
```

## License

Rayuela is a free software and content project:

- The source code is licensed under the **GNU General Public License v3.0 or later (GPLv3+)**. See the [LICENSE](LICENSE) file for details.
- The site content is licensed under the **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)**. See the [CONTENT-LICENSE.md](CONTENT-LICENSE.md) file for details.
