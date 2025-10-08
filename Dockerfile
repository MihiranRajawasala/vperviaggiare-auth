FROM node:20-alpine
USER node
WORKDIR /app
COPY --chown=node:node package*.json ./
RUN npm ci --omit=dev
COPY --chown=node:node . .
EXPOSE 4000
CMD ["node", "server.js"]
