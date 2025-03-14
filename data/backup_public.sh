#!/bin/bash

if [ ! -d $HOME/backup ]
then
    echo "Creating $HOME/backup"
    mkdir $HOME/backup
fi

DATE=`date +'%Y-%m-%d-%H-%M-%S'`
BACKUP_FILE="$HOME/backup/public-$DATE.tar"

tar -cvf $BACKUP_FILE /mnt/octopus_server_public/
bzip2 -9 $BACKUP_FILE
