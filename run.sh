#!/bin/sh
docker run --rm \
  -v /etc/letsencrypt/live/myip.blue-0001/privkey.pem:/key.pem:ro \
  -v /etc/letsencrypt/live/myip.blue-0001/fullchain.pem:/chain.pem:ro \
  -p 8080:80 -p 8081:443 myip.dev
