#!/usr/bin/env bash

NEXT_PUBLIC_BASE_URL=$NEXT_PUBLIC_BASE_URL PORT=$PORT sh ./frontend-start.sh &
./sqlx migrate run
./octopus_server
