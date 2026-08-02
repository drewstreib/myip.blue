#!/bin/sh
docker build -t myip .
cd ..
docker compose up -d
cd myip.blue
