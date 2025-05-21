#!/bin/bash

NOW=$(date '+%Y-%m-%d %H:%M:%S')
BANNED_IPS=$(sudo fail2ban-client status sshd 2>/dev/null | grep 'Banned IP list:' | cut -d ':' -f2 | xargs)
RECORD_FILE="/home/sistemodev/SSH-Koruma/ip_logger/ip_ban_records.log"

# Log kaydı
echo "[$NOW] Banned IPs: $BANNED_IPS" >>"$RECORD_FILE"

# Mail bildirimi
if [ -n "$BANNED_IPS" ]; then
    echo -e "[$NOW] Tarihli Engelli IP'ler Listesi: $BANNED_IPS" |
        mail -s "[SSH Koruma] Fail2Ban Engellenen IP'ler" zzehrakr48@gmail.com
    echo -e "[$NOW] Tarihli Engelli IP'ler Listesi: $BANNED_IPS" |
        mail -s "[SSH Koruma] Fail2Ban Engellenen IP'ler" b.pekalp@gmail.com
fi
