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
case "$ACTION" in
block)
    # Daha önce aynı kural var mı kontrol et
    if sudo iptables -C INPUT -s "$IP" -j DROP 2>/dev/null; then
        echo "$IP zaten engellenmiş."
    else
        sudo iptables -A INPUT -s "$IP" -j DROP
        echo "$IP engellendi."
    fi
    ;;
allow)
    # DROP kuralı varsa sil
    if sudo iptables -C INPUT -s "$IP" -j DROP 2>/dev/null; then
        sudo iptables -D INPUT -s "$IP" -j DROP
        echo "$IP engeli kaldırıldı."
    else
        echo "$IP için engel bulunamadı."
    fi
    ;;
*)
    echo "Geçersiz işlem: $ACTION (block veya allow olmalı)"
    exit 3
    ;;
esac
