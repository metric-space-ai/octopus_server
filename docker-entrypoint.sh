#!/usr/bin/env bash

NEXT_PUBLIC_BASE_URL=$NEXT_PUBLIC_BASE_URL NEXT_PUBLIC_DOMAIN=$NEXT_PUBLIC_DOMAIN PORT=$PORT sh ./frontend-start.sh &
./sqlx migrate run
./octopus_server
