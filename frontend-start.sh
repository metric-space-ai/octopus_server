#!/usr/bin/env bash

cd /octopus_client
npm install --frozen-lockfile
#npm run lint
NEXT_PUBLIC_BASE_URL=$NEXT_PUBLIC_BASE_URL NEXT_PUBLIC_DOMAIN=$NEXT_PUBLIC_DOMAIN NEXT_PUBLIC_THEME_NAME=$NEXT_PUBLIC_THEME_NAME npm run custom-start
