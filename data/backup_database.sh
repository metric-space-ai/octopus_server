#!/bin/bash

if [ ! -d $HOME/backup ]
then
    echo "Creating $HOME/backup"
    mkdir $HOME/backup
fi

DATE=`date +'%Y-%m-%d-%H-%M-%S'`
BACKUP_FILE="$HOME/backup/octopus_server-$DATE.sql"

pg_dump -U postgres -h localhost -d octopus_server > $BACKUP_FILE
bzip2 -9 $BACKUP_FILE
