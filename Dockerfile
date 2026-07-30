# syntax=docker/dockerfile:1
FROM node:20-slim AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:20-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json* ./
RUN npm install --omit=dev
COPY --from=build /app/dist ./dist
COPY db ./db

# Runs unprivileged; mount SECURESTORE_SOCKET_PATH's parent dir if using a UDS.
RUN useradd --uid 10001 --create-home securestore
USER securestore

EXPOSE 8443
CMD ["node", "dist/server.js"]
