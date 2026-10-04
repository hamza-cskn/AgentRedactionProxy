FROM node:24-bookworm-slim
WORKDIR /app
COPY --chown=node:node package.json config.json ./
COPY --chown=node:node src ./src
COPY --chown=node:node scripts ./scripts
RUN mkdir /data && chown node:node /data && chmod 700 /data
ENV ARP_DATA_DIR=/data ARP_LISTEN_HOST=0.0.0.0
USER node
EXPOSE 8787 8788
CMD ["node", "src/main.mjs"]
