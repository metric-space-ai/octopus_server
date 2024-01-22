#!/usr/bin/env bash

. /root/.ghcup/env
cd /wasp_mage
DATABASE_URL=$WASP_MAGE_DATABASE_URL wasp db migrate-dev
sed -i "s/    port: 3000,/    port: $WASP_MAGE_PORT,/g" /wasp_mage/.wasp/out/web-app/vite.config.ts
DATABASE_URL=$WASP_MAGE_DATABASE_URL PORT=$WASP_MAGE_BACKEND_PORT wasp start
