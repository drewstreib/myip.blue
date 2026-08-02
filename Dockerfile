# Zero runtime dependencies, so there is no install stage and no node_modules.
FROM node:22-alpine

WORKDIR /app

# Copy explicitly rather than `COPY . .` — nothing enters the image that is not
# named here, so a stray file in the working tree cannot be shipped by accident.
COPY package.json ./
COPY index.js ./
COPY lib ./lib
COPY static ./static

# ⚠️ Runs as non-root. Binding 80/443 therefore needs NET_BIND_SERVICE granted
# by the runtime (compose: cap_add), or HTTP_PORT/HTTPS_PORT set above 1024.
# The old image ran as root purely to bind those ports.
USER node

EXPOSE 80 443

# `node` directly, not `npm run start`. npm as PID 1 cost ~31MB RSS on a 405MB
# box, swallowed signals, and made every stop exit 1 after ~2.1s instead of 143.
CMD ["node", "index.js"]
