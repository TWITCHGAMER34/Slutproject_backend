FROM node:alpine3.15 AS builder
WORKDIR /app

COPY ./package.json ./package.json

RUN npm i --legacy-peer-deps

COPY ./ ./

CMD ["node", "."]