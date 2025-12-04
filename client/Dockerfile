# stage 1: build
FROM node:22-alpine AS build

WORKDIR /client

COPY package.json package-lock.json* ./
COPY tsconfig.json vite.config.ts ./

RUN npm install

COPY index.html ./
COPY src ./src

RUN npm run build

# stage 2: nginx
FROM nginx:alpine

COPY src/nginx.conf /etc/nginx/nginx.conf

COPY --from=build /client/dist /usr/share/nginx/html
