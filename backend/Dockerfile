
FROM node:20-alpine AS base
WORKDIR /app


COPY package.json ./
RUN npm install --production

# Copy source
COPY api/ ./api/


RUN npm install express --save


COPY docker-server.js ./

EXPOSE 3001
ENV PORT=3001
ENV NODE_ENV=production

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://localhost:3001/health || exit 1

CMD ["node", "docker-server.js"]
