#!/bin/bash

git clone https://github.com/letsencrypt/pebble
cd pebble && go install ./cmd/pebble || exit 1
pebble &
disown
