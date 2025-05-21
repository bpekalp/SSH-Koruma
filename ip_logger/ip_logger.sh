#!/bin/bash

# Tarih
NOW=$(date '+%Y-%m-%d %H:%M:%S')

# Engellenen IP'ler
BANNED_IPS=$(sudo fail2ban-client status sshd 2>/dev/null | grep 'Banned IP list:' | cut -d ':' -f2 | xargs)

# Kayıt dosyası
RECORD_FILE="/var/log/ip_ban_records.log"

# Kaydı dosyaya yazma (manuel inceleme için)
echo "[$NOW] Banned IPs: $BANNED_IPS" >>$RECORD_FILE]

# Kaydı bildirim olarak göndermek
if [ -n "$BANNED_IPS" ]; then
    echo -e "[$NOW] Tarihli Engelli IP'ler Listesi: $BANNED_IPS" | mail -s "[SSH Koruma] Fail2Ban Engellenen IP'ler" -c b.pekalp@gmail.com zzehrakr48@gmail.com
fi
