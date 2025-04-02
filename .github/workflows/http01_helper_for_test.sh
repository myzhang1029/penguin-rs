#!/bin/sh

token="$(echo "$2"|cut -d. -f1)"
WEBROOT="$(dirname "$0")"

echo "WEBROOT: $WEBROOT"

if [ "$1" = "create" ]; then
    mkdir -p "$WEBROOT/.well-known/acme-challenge"
    echo "$2" > "$WEBROOT/.well-known/acme-challenge/$token"
elif [ "$1" = "remove" ]; then
    rm "$WEBROOT/.well-known/acme-challenge/$token"
fi
