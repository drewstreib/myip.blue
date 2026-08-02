#!/bin/sh
#docker run --rm -v "$PWD:/work" tmknom/prettier --parser=markdown --write '**/*.md'
npx prettier --write *.js 
