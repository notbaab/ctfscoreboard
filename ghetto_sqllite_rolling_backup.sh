#!/bin/bash

# worlds most robust sqlite3 backup script

database=$1
while [[ 1 ]]; do
   for i in `seq 1 5`;
    do
    	echo "Backing up to ${database}.db_${i}.bak"
		sqlite3 ${database} ".backup ${database}.db_${i}.bak"
		sleep 5m
    done
done

