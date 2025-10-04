# Usar una imagen base de Node.js consistente
FROM node:20-alpine

# Establecer el directorio de trabajo
WORKDIR /usr/src/app

# Copiar solo los archivos de manifiesto del paquete para aprovechar el caché de Docker
COPY package*.json ./

# Instalar dependencias (esto se ejecutará dentro del contenedor Alpine)
RUN npm install

# Copiar el resto del código (esto será sobrescrito por el volumen de docker-compose, pero es buena práctica tenerlo)
COPY . .

# El comando para iniciar la app en modo de desarrollo (usando ts-node-dev o similar)
# docker-compose anulará este CMD, pero lo dejamos como referencia.
CMD ["npm", "run", "start:dev"]
