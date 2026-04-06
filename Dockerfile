# ─── Stage 1: Build ───────────────────────────────────────────────────────────
# Usamos Node 20 sobre Alpine (imagen liviana) como entorno de compilación
FROM node:20-alpine AS build

# Directorio de trabajo dentro del contenedor donde se copiará el código
WORKDIR /usr/src/app

# Copiamos solo los manifiestos de dependencias primero para aprovechar
# la caché de capas de Docker: si package*.json no cambia, npm install no se repite
COPY package*.json ./

# Instalamos todas las dependencias (incluyendo devDependencies necesarias para compilar)
RUN npm install

# Copiamos el resto del código fuente
COPY . .

# Compilamos TypeScript a JavaScript (genera la carpeta dist/)
RUN npm run build

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
# Nueva imagen limpia de Node 20 Alpine; no incluye el código fuente ni devDependencies
FROM node:20-alpine

# Mismo directorio de trabajo que en la etapa de build
WORKDIR /usr/src/app

# Copiamos los manifiestos para instalar solo dependencias de producción
COPY package*.json ./

# Instalamos únicamente las dependencias de producción (sin devDependencies)
RUN npm install --only=production

# Copiamos el código compilado desde la etapa de build
COPY --from=build /usr/src/app/dist ./dist

# Exponemos el puerto en el que escucha la aplicación NestJS
EXPOSE 3000

# Comando de inicio: ejecuta el archivo principal compilado
CMD ["node", "dist/src/main"]
