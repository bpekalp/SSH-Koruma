import streamlit as st
import subprocess
import time
import re
from collections import Counter

st.set_page_config(page_title="SSH Güvenlik Paneli", layout="wide")
st.title("🛡️ SSH Güvenlik Dashboard")

# Otomatik yenileme düğmesi
st.sidebar.header("🧰 Kontroller")
refresh = st.sidebar.button("🔄 Verileri Yenile")


# Engellenen IP'ler
def get_banned_ips():
    try:
        result = subprocess.check_output(
            "sudo fail2ban-client status sshd", shell=True
        ).decode()
        banned = [line for line in result.splitlines() if "Banned IP list" in line]
        return banned[0].split(":")[1].strip().split()
    except Exception as e:
        return [f"Hata: {str(e)}"]


st.subheader("🚫 Engellenen IP'ler")
if refresh:
    banned_ips = get_banned_ips()
    st.code("\n".join(banned_ips) if banned_ips else "Şu anda engellenmiş IP yok.")


# Aktif SSH oturumları
def get_active_sessions():
    return subprocess.getoutput("who | grep 'pts/' || echo 'Aktif SSH oturumu yok'")


st.subheader("🧑‍💻 Aktif SSH Oturumları")
if refresh:
    st.text(get_active_sessions())


# SSH giriş denemelerini çek
@st.cache_data(ttl=30)
def get_ssh_login_attempts():
    return subprocess.getoutput(
        "sudo cat /var/log/auth.log | grep -E 'Failed password|Accepted password' | tail -n 100"
    )


# Loglardan istatistik çıkar
def get_login_stats(log_data):
    success = len(re.findall(r"Accepted password", log_data))
    failed = len(re.findall(r"Failed password", log_data))
    return success, failed


# IP adreslerini çıkar
def extract_ips(log_data):
    return re.findall(r"from ([\d.]+)", log_data)


# Analizleri ve diğer her şeyi yukarıda göster
if refresh:
    raw_logs = get_ssh_login_attempts()

    # İstatistikler
    success_count, failed_count = get_login_stats(raw_logs)
    st.markdown("### 📊 Giriş İstatistikleri")
    col1, col2 = st.columns(2)
    col1.metric("✅ Başarılı Giriş", success_count)
    col2.metric("❌ Başarısız Giriş", failed_count)

    # En çok deneyen IP'ler
    ip_counts = Counter(extract_ips(raw_logs))
    if ip_counts:
        st.markdown("### 🧠 En Çok Giriş Denemesi Yapan IP’ler")
        for ip, count in ip_counts.most_common(5):
            st.write(f"🔹 `{ip}` → {count} kez")

    # Fail2Ban durum bilgisi
    st.markdown("### 🟢 Fail2Ban Servis Durumu")
    service_status = subprocess.getoutput("systemctl is-active fail2ban")
    if service_status.strip() == "active":
        st.success("Fail2Ban çalışıyor ✅")
    else:
        st.error("Fail2Ban aktif değil! ❌")

    # Log indir
    st.download_button("📥 auth.log indir", data=raw_logs, file_name="auth_excerpt.log")

# En alta SSH giriş denemelerini koy
if refresh:
    st.markdown("---")
    st.subheader("🔐 SSH Giriş Denemeleri (Başarılı / Başarısız)")
    st.text(raw_logs)
else:
    st.info("🔄 Logları görmek için soldan 'Verileri Yenile' butonuna bas.")
