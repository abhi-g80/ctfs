#!/bin/bash

JOHN=john

usage() {
    echo "usage: $1 <cookie_file> <wordlist>"
    exit 1
}

command -v $JOHN 2>&1 > /dev/null
if [[ "$?" -ne 0 ]]; then
    echo "`$JOHN` not found in PATH"
    echo "Install john-the-ripper: sudo apt install john -y"
    exit 1
fi

if [[ "$#" -ne 2 ]]; then
    usage $0
fi

COOKIE_FILE=$1
WORDLIST_FILE=$2

john "$1" --wordlist="$2" --format=HMAC-SHA256
john --show "$1"
