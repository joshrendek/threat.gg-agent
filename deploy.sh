#!/bin/bash
HOSTS=(45.32.7.250 185.92.220.13 45.32.63.226 192.3.168.227)

GOOS=linux go build -o honeypot commands.go sshd.go persistence.go

for h in "${HOSTS[@]}"; do
    ssh root@$h -p 2222 'mv honeypot honeypot.old | true'
    scp -P 2222 honeypot root@$h:~/
    scp -P 2222 honeypot.conf root@$h:/etc/init/honeypot.conf
    ssh root@$h -p 2222 'restart honeypot'
done
