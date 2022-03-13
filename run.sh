#!/bin/sh
docker run --rm \
  -v /etc/letsencrypt/live/myip.blue-0001/privkey.pem:/key.pem:ro \
  -v /etc/letsencrypt/live/myip.blue-0001/fullchain.pem:/chain.pem:ro \
  -p 8080:8080 -p 8081:8081 myip.dev
