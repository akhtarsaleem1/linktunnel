FROM node:22-alpine

WORKDIR /app
COPY package.json ./
COPY bin ./bin
COPY src ./src

ENV PORT=4320
EXPOSE 4320

CMD ["node", "bin/linktunnel.mjs", "relay", "--host", "0.0.0.0"]
