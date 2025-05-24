import streamlit as st
import subprocess
import re
from collections import Counter

st.set_page_config(page_title="SSH Güvenlik Paneli", layout="wide")
st.title("🛡️ SSH Güvenlik Dashboard")

# Veri yenileme butonu
st.sidebar.header("🧰 Kontroller")
refresh = st.sidebar.button("🔄 Verileri Yenile")


# IP doğrulama fonksiyonu
def is_valid_ip(ip):
    return re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip)


# IP engelleme fonksiyonu
def block_ip(ip):
    try:
        result = subprocess.check_output(
            f"sudo /home/sistemodev/SSH-Koruma/iptables/ip_rule.sh {ip} block",
            shell=True,
            stderr=subprocess.STDOUT,
        ).decode()
        return True, result
    except subprocess.CalledProcessError as e:
        return False, e.output.decode()


# IP engel kaldırma fonksiyonu
def unblock_ip(ip):
    try:
        subprocess.check_output(
            f"sudo /home/sistemodev/SSH-Koruma/iptables/ip_rule.sh {ip} allow",
            shell=True,
            stderr=subprocess.STDOUT,
        )
        return True
    except subprocess.CalledProcessError:
        return False


# Fail2Ban IP listesini al
def get_banned_ips():
    try:
        result = subprocess.check_output(
            "sudo fail2ban-client status sshd", shell=True
        ).decode()
        banned = [line for line in result.splitlines() if "Banned IP list" in line]
        return banned[0].split(":")[1].strip().split()
    except Exception as e:
        return [f"Hata: {str(e)}"]


# iptables DROP IP listesini al
def get_manual_blocked_ips():
    try:
        result = subprocess.check_output(
            "sudo iptables -S | grep 'DROP'", shell=True
        ).decode()
        return sorted(set(re.findall(r"-s ([\d.]+)", result)))
    except Exception as e:
        return []


# Aktif SSH oturumlarını göster
def display_active_sessions():
    st.subheader("🧑‍💻 Aktif SSH Oturumları")
    output = subprocess.getoutput("who | grep 'pts/' || echo 'Aktif SSH oturumu yok'")
    st.text(output)


# Fail2Ban durumunu göster
def show_fail2ban_status():
    st.markdown("### 🟢 Fail2Ban Servis Durumu")
    status = subprocess.getoutput("systemctl is-active fail2ban").strip()
    if status == "active":
        st.success("Fail2Ban çalışıyor ✅")
    else:
        st.error("Fail2Ban aktif değil! ❌")


# SSH loglarını al
@st.cache_data(ttl=30)
def get_ssh_login_attempts():
    return subprocess.getoutput(
        "sudo grep -E 'sshd.*(Failed password|Accepted password)' /var/log/auth.log | tail -n 50"
    )


# Loglardan istatistik çıkar
def get_login_stats(log_data):
    success = len(re.findall(r"Accepted password", log_data))
    failed = len(re.findall(r"Failed password", log_data))
    return success, failed


# IP'leri çıkart
def extract_ips(log_data):
    return re.findall(r"from ([\d.]+)", log_data)


# Giriş istatistiklerini ve IP analizini göster
def display_login_statistics(log_data):
    success, failed = get_login_stats(log_data)
    st.markdown("### 📊 Giriş İstatistikleri")
    col1, col2 = st.columns(2)
    col1.metric("✅ Başarılı Giriş", success)
    col2.metric("❌ Başarısız Giriş", failed)

    ip_counts = Counter(extract_ips(log_data))
    if ip_counts:
        st.markdown("### 🧠 En Çok Giriş Denemesi Yapan IP’ler")
        for ip, count in ip_counts.most_common(5):
            st.write(f"🔹 `{ip}` → {count} kez")


# IP Kara Liste Ekleme Paneli
st.markdown("### ⛔ Manuel IP Kara Liste Ekle")
ip_to_block = st.text_input("Engellenecek IP adresini girin:")
if st.button("🚫 Kara Listeye Ekle"):
    if ip_to_block:
        if is_valid_ip(ip_to_block):
            success, output = block_ip(ip_to_block)
            if success:
                st.success(f"✅ {ip_to_block} kara listeye eklendi.")
                st.text(output)
            else:
                st.error(f"❌ Hata oluştu:\n{output}")
        else:
            st.warning("⚠️ Geçersiz IP adresi formatı.")
    else:
        st.warning("⚠️ Lütfen bir IP adresi girin.")


# Fail2Ban IP'leri göster
st.subheader("🚫 Fail2Ban Tarafından Engellenen IP'ler")
if refresh:
    banned_ips = get_banned_ips()
    st.code("\n".join(banned_ips) if banned_ips else "Şu anda engellenmiş IP yok.")


# Manuel olarak engellenen IP'ler ve kaldırma
st.subheader("🛡️ Manuel Olarak Engellenen IP'ler (iptables)")
manual_ips = get_manual_blocked_ips()
if manual_ips:
    for ip in manual_ips:
        col1, col2 = st.columns([4, 1])
        col1.code(ip)
        if col2.button(f"❌ Kaldır", key=f"unblock_{ip}"):
            if unblock_ip(ip):
                st.success(f"{ip} engeli kaldırıldı.")
                st.rerun()
            else:
                st.error(f"{ip} engeli kaldırılamadı.")
else:
    st.info("Şu anda manuel olarak engellenmiş IP yok.")


# Aktif SSH oturumları göster
if refresh:
    display_active_sessions()


# SSH loglarını işle
if refresh:
    raw_logs = get_ssh_login_attempts()
    display_login_statistics(raw_logs)
    show_fail2ban_status()
    st.download_button("📥 auth.log indir", data=raw_logs, file_name="auth_excerpt.log")
    st.markdown("---")
    st.subheader("🔐 SSH Giriş Denemeleri (Sadece sshd logları)")
    st.text(raw_logs)
else:
    st.info("🔄 Logları görmek için soldan 'Verileri Yenile' butonuna bas.")
