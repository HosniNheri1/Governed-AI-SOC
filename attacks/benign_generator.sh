#!/bin/bash
# Simulates normal usage: occasional web hits, one correct login, rare single failed login
for i in $(seq 1 5); do
    curl -s http://172.30.0.10:8080/ -o /dev/null
    sleep $((RANDOM % 5 + 2))
done

# One correct login (not a brute force - single attempt)
curl -s -X POST http://172.30.0.10:8080/ -d "username=admin&password=correcthorse" -o /dev/null
sleep 3

# One incidental failed login (realistic - someone fat-fingers a password once)
curl -s -X POST http://172.30.0.10:8080/ -d "username=admin&password=oops" -o /dev/null
sleep 2

# A normal FTP connection check (not brute force)
curl -s ftp://172.30.0.10/ -u ftp: --max-time 3 -o /dev/null 2>/dev/null

echo "Benign session complete."
