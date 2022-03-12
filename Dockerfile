FROM node:16 AS base
WORKDIR /build
COPY package*.json ./
#RUN npm install --save express
RUN npm install
# RUN npm ci --only=production


#####################3
FROM node:16-alpine AS release
WORKDIR /app
#RUN npm install --save express
# copy production node_modules
COPY --from=base /build/node_modules ./node_modules

COPY . .

EXPOSE 8080
ENV DEBUG=express:*
CMD ["npm","run","start"]
