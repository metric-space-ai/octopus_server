#!/usr/bin/env bash

cd /octopus_client
npm install --frozen-lockfile
npm run lint
NEXT_PUBLIC_BASE_URL=$NEXT_PUBLIC_BASE_URL NEXT_PUBLIC_DOMAIN=$NEXT_PUBLIC_DOMAIN npm run custom-start
