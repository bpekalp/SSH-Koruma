import streamlit as st
import subprocess
import re
from collections import Counter

st.set_page_config(page_title="SSH Güvenlik Paneli", layout="wide")
st.title("🛡️ SSH Güvenlik Dashboard")

# Otomatik yenileme düğmesi
st.sidebar.header("🧰 Kontroller")
refresh = st.sidebar.button("🔄 Verileri Yenile")

# Manuel IP Kara Listeye Ekle (ip_rule.sh ile entegre)
st.markdown("### ⛔ Manuel IP Kara Liste Ekle")
ip_to_block = st.text_input("Engellenecek IP adresini girin:")
if st.button("🚫 Kara Listeye Ekle"):
    if ip_to_block:
        try:
            result = subprocess.check_output(
                f"sudo /home/sistemodev/SSH-Koruma/iptables/ip_rule.sh {ip_to_block} block",
                shell=True,
                stderr=subprocess.STDOUT,
            ).decode()
            st.success(f"✅ {ip_to_block} kara listeye eklendi.")
            st.text(result)
        except subprocess.CalledProcessError as e:
            st.error(f"❌ Hata oluştu:\n{e.output.decode()}")
    else:
        st.warning("⚠️ Lütfen bir IP adresi girin.")


# Fail2Ban tarafından engellenen IP'leri al
def get_banned_ips():
    try:
        result = subprocess.check_output(
            "sudo fail2ban-client status sshd", shell=True
        ).decode()
        banned = [line for line in result.splitlines() if "Banned IP list" in line]
        return banned[0].split(":")[1].strip().split()
    except Exception as e:
        return [f"Hata: {str(e)}"]


st.subheader("🚫 Fail2Ban Tarafından Engellenen IP'ler")
if refresh:
    banned_ips = get_banned_ips()
    st.code("\n".join(banned_ips) if banned_ips else "Şu anda engellenmiş IP yok.")


# iptables'dan manuel engellenmiş IP'leri al
def get_manual_blocked_ips():
    try:
        result = subprocess.check_output(
            "sudo iptables -S | grep 'DROP'", shell=True
        ).decode()
        lines = result.strip().split("\n")
        ip_entries = []
        for line in lines:
            match = re.search(r"-s ([\d.]+)", line)
            if match:
                ip = match.group(1)
                ip_entries.append(ip)
        return sorted(set(ip_entries))
    except Exception as e:
        return []


# ip_rule.sh ile IP engel kaldırma
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


# Manuel engellenen IP'leri listele ve kaldır
st.subheader("🛡️ Manuel Olarak Engellenen IP'ler (iptables)")
manual_blocked_ips = get_manual_blocked_ips()
if manual_blocked_ips:
    for ip in manual_blocked_ips:
        col1, col2 = st.columns([4, 1])
        col1.code(ip)
        if col2.button(f"❌ Kaldır", key=f"unblock_{ip}"):
            success = unblock_ip(ip)
            if success:
                st.success(f"{ip} engeli kaldırıldı.")
                st.experimental_rerun()
            else:
                st.error(f"{ip} engeli kaldırılamadı.")
else:
    st.info("Şu anda manuel olarak engellenmiş IP yok.")


# Aktif SSH oturumları
def get_active_sessions():
    return subprocess.getoutput("who | grep 'pts/' || echo 'Aktif SSH oturumu yok'")


st.subheader("🧑‍💻 Aktif SSH Oturumları")
if refresh:
    st.text(get_active_sessions())


# SSH giriş denemeleri
@st.cache_data(ttl=30)
def get_ssh_login_attempts():
    return subprocess.getoutput(
        "sudo grep -E 'sshd.*(Failed password|Accepted password)' /var/log/auth.log | tail -n 100"
    )


# Giriş istatistikleri
def get_login_stats(log_data):
    success = len(re.findall(r"Accepted password", log_data))
    failed = len(re.findall(r"Failed password", log_data))
    return success, failed


# IP’leri çıkart
def extract_ips(log_data):
    return re.findall(r"from ([\d.]+)", log_data)


# Giriş verileri
if refresh:
    raw_logs = get_ssh_login_attempts()

    # Giriş istatistikleri
    success_count, failed_count = get_login_stats(raw_logs)
    st.markdown("### 📊 Giriş İstatistikleri")
    col1, col2 = st.columns(2)
    col1.metric("✅ Başarılı Giriş", success_count)
    col2.metric("❌ Başarısız Giriş", failed_count)

    # En çok deneme yapan IP'ler
    ip_counts = Counter(extract_ips(raw_logs))
    if ip_counts:
        st.markdown("### 🧠 En Çok Giriş Denemesi Yapan IP’ler")
        for ip, count in ip_counts.most_common(5):
            st.write(f"🔹 `{ip}` → {count} kez")

    # Fail2Ban servis durumu
    st.markdown("### 🟢 Fail2Ban Servis Durumu")
    service_status = subprocess.getoutput("systemctl is-active fail2ban")
    if service_status.strip() == "active":
        st.success("Fail2Ban çalışıyor ✅")
    else:
        st.error("Fail2Ban aktif değil! ❌")

    # Log indir
    st.download_button("📥 auth.log indir", data=raw_logs, file_name="auth_excerpt.log")

# SSH loglarını göster
if refresh:
    st.markdown("---")
    st.subheader("🔐 SSH Giriş Denemeleri (Sadece sshd logları)")
    st.text(raw_logs)
else:
    st.info("🔄 Logları görmek için soldan 'Verileri Yenile' butonuna bas.")
