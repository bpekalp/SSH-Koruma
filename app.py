import streamlit as st
import subprocess

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


# Brute-force denemeleri
@st.cache_data(ttl=30)
def get_failed_logins():
    return subprocess.getoutput(
        "sudo grep 'Failed password' /var/log/auth.log | tail -n 20"
    )


st.subheader("🔐 SSH Brute-Force Girişim Kayıtları")
if refresh:
    st.text(get_failed_logins())
else:
    st.info("🔄 Yenile düğmesine basarak verileri güncelleyebilirsin.")
