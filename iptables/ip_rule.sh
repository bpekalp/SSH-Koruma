#!/bin/bash

IP=$1
ACTION=$2

# Hatalı kullanım uyarısı
if [[ -z "$IP" || -z "$ACTION" ]]; then
    echo "Kullanım: $0 <IP_ADRESİ> <block veya allow>"
    exit 1
fi

# IP adres kontrolü
if ! [[ $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Hatalı IP formatı: $IP"
    exit 2
fi

# Engel veya İzin verme
if [ "$ACTION" == "block" ]; then
    sudo iptables -A INPUT -s "$IP" -j DROP
    echo "$IP engellendi (DROP eklendi)"
elif [ "$ACTION" == "allow" ]; then
    sudo iptables -D INPUT -s "$IP" -j DROP
    echo "$IP engeli kaldırıldı (DROP silindi)"
else
    echo "Geçersiz işlem: $ACTION (block ya da allow olmalı)"
    exit 3
fi