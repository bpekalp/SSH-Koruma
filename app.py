import streamlit as st
import subprocess

st.set_page_config(page_title="SSH Güvenlik Paneli", layout="wide")
st.title("🛡️ SSH Güvenlik Dashboard")


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
banned_ips = get_banned_ips()
st.code("\n".join(banned_ips) if banned_ips else "Şu anda engellenmiş IP yok.")

st.subheader("🧑‍💻 Aktif SSH Oturumları")
ssh_sessions = subprocess.getoutput("who | grep 'pts/' || echo 'Aktif SSH oturumu yok'")
st.text(ssh_sessions)

st.subheader("🔐 SSH Brute-Force Girişim Kayıtları")
failed_logins = subprocess.getoutput(
    "sudo grep 'Failed password' /var/log/auth.log | tail -n 20"
)
st.text(failed_logins)
