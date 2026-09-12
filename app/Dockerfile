FROM node:20-slim

WORKDIR /usr/src/app

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY . .

ENV PORT=3075
ENV LOG_DIR=/opt/admin/logs

EXPOSE 3075

CMD ["node", "server.js"]
