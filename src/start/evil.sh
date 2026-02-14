#!/bin/bash
IPS=("192.256.1.1" "192.256.1.2" "192.256.1.3" "192.256.1.4" "192.256.1.5" "192.256.1.6" "192.256.1.7" "192.256.1.8" "192.256.1.9" "192.256.1.10")

for i in {1..1000}
do
    IP=${IPS[$(($RANDOM % 10))]}
    curl -X POST http://localhost:3000/task \
      -H "X-Forwarded-For: $IP" \
      -H "Content-Type: application/json" \
      -d '{"task":"foo"}'
    sleep 0.5
done