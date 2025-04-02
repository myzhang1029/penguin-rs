#!/bin/bash

kill $(lsof -t -i :5002)
kill $(lsof -t -i :14000)
kill $(lsof -t -i :15000)
git clone https://github.com/letsencrypt/pebble
cd pebble && go install ./cmd/pebble || exit 1
pebble &
disown
