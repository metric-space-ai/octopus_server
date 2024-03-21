#!/usr/bin/env bash

NEXT_PUBLIC_BASE_URL=$NEXT_PUBLIC_BASE_URL NEXT_PUBLIC_DOMAIN=$NEXT_PUBLIC_DOMAIN PORT=$PORT sh ./frontend-start.sh &
OPENAI_API_KEY=$OPENAI_API_KEY WASP_MAGE_DATABASE_URL=$WASP_MAGE_DATABASE_URL WASP_MAGE_BACKEND_PORT=$WASP_MAGE_BACKEND_PORT WASP_MAGE_PORT=$WASP_MAGE_PORT sh ./wasp-mage-start.sh &
/usr/bin/supervisord --configuration /etc/supervisord.conf &
./sqlx migrate run
./octopus_server
