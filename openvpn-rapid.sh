#!/usr/bin/env bash
set -euo pipefail

# OpenVPN rapid installer - modernized
# Supports: Debian, Ubuntu, Fedora, CentOS/RHEL/Rocky/Alma, Arch
# Requires: root, systemd, /dev/net/tun

EASYRSA_VERSION="3.2.6"
VPN_SUBNET="10.8.0.0"
VPN_NETMASK="255.255.255.0"
VPN_CIDR="10.8.0.0/24"
VPN_DNS_IP="10.8.0.1"
OPENVPN_DIR="/etc/openvpn"
SERVER_DIR="/etc/openvpn/server"
CLIENT_TEMPLATE="/etc/openvpn/client-template.txt"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
PKI_DIR="/etc/openvpn/easy-rsa/pki"
LOG_DIR="/var/log/openvpn"
SERVER_CONF="${SERVER_DIR}/server.conf"

is_root() {
	[[ "${EUID}" -eq 0 ]]
}

tun_check() {
	[[ -e /dev/net/tun ]]
}

detect_os() {
	if [[ -e /etc/os-release ]]; then
		. /etc/os-release
		OS_ID="${ID}"
		OS_VERSION="${VERSION_ID:-}"
	else
		echo "Cannot detect OS."
		exit 1
	fi

	case "${OS_ID}" in
		debian|ubuntu)
			OS_FAMILY="debian"
			;;
		fedora)
			OS_FAMILY="fedora"
			;;
		centos|rhel|rocky|almalinux)
			OS_FAMILY="rhel"
			;;
		arch|manjaro)
			OS_FAMILY="arch"
			;;
		*)
			echo "Unsupported OS: ${OS_ID}"
			exit 1
			;;
	esac
}

initial_check() {
	if ! is_root; then
		echo "This script must be run as root."
		exit 1
	fi

	if ! tun_check; then
		echo "TUN device is not available at /dev/net/tun."
		exit 1
	fi

	if ! command -v systemctl >/dev/null 2>&1; then
		echo "This script requires systemd."
		exit 1
	fi

	detect_os
}

install_packages() {
	case "${OS_FAMILY}" in
		debian)
			apt-get update
			apt-get install -y openvpn openssl ca-certificates curl wget tar iproute2 iptables
			;;
		fedora)
			dnf install -y openvpn openssl ca-certificates curl wget tar iproute iptables
			;;
		rhel)
			if ! rpm -q epel-release >/dev/null 2>&1; then
				dnf install -y epel-release || yum install -y epel-release
			fi
			dnf install -y openvpn openssl ca-certificates curl wget tar iproute iptables || \
			yum install -y openvpn openssl ca-certificates curl wget tar iproute iptables
			;;
		arch)
			pacman --needed --noconfirm -Syu openvpn openssl ca-certificates curl wget tar iproute2 iptables
			;;
	esac
}

install_unbound() {
	case "${OS_FAMILY}" in
		debian)
			apt-get install -y unbound
			;;
		fedora|rhel)
			dnf install -y unbound || yum install -y unbound
			;;
		arch)
			pacman --needed --noconfirm -S unbound
			;;
	esac

	mkdir -p /etc/unbound/unbound.conf.d

	cat > /etc/unbound/unbound.conf.d/openvpn.conf <<EOF
server:
	interface: ${VPN_DNS_IP}
	access-control: ${VPN_CIDR} allow
	hide-identity: yes
	hide-version: yes
	use-caps-for-id: yes
	prefetch: yes
	qname-minimisation: yes
	private-address: 10.0.0.0/8
	private-address: 172.16.0.0/12
	private-address: 192.168.0.0/16
	private-address: 169.254.0.0/16
	private-address: 127.0.0.0/8
EOF

	if [[ -f /etc/unbound/unbound.conf ]] && ! grep -q "unbound.conf.d" /etc/unbound/unbound.conf; then
		echo 'include: "/etc/unbound/unbound.conf.d/*.conf"' >> /etc/unbound/unbound.conf
	fi

	systemctl enable --now unbound
	systemctl restart unbound
}

public_ip() {
	curl -fsS4 https://ifconfig.co || true
}

detect_private_ip() {
	local ip="$1"
	[[ "${ip}" =~ ^10\. ]] || \
	[[ "${ip}" =~ ^192\.168\. ]] || \
	[[ "${ip}" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]
}

detect_local_ip() {
	ip -4 addr show scope global | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1
}

detect_nic() {
	ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1
}

install_questions() {
	echo "Welcome to the Rapid OpenVPN installer."
	echo

	IP="$(detect_local_ip)"
	read -rp "IPv4 address OpenVPN should listen on [${IP}]: " INPUT_IP
	IP="${INPUT_IP:-$IP}"

	if detect_private_ip "${IP}"; then
		DEFAULT_ENDPOINT="$(public_ip)"
		read -rp "Public IPv4 address or hostname [${DEFAULT_ENDPOINT}]: " ENDPOINT
		ENDPOINT="${ENDPOINT:-$DEFAULT_ENDPOINT}"
	else
		ENDPOINT="${IP}"
	fi

	read -rp "OpenVPN port [1194]: " PORT
	PORT="${PORT:-1194}"

	echo "Protocol:"
	echo "  1) UDP"
	echo "  2) TCP"
	read -rp "Protocol [1]: " PROTOCOL_CHOICE
	PROTOCOL_CHOICE="${PROTOCOL_CHOICE:-1}"

	if [[ "${PROTOCOL_CHOICE}" == "2" ]]; then
		PROTOCOL="tcp"
		CLIENT_PROTO="tcp-client"
	else
		PROTOCOL="udp"
		CLIENT_PROTO="udp"
	fi

	echo "DNS provider:"
	echo "  1) Current system resolvers"
	echo "  2) Self-hosted Unbound"
	echo "  3) Cloudflare"
	echo "  4) Quad9"
	echo "  5) OpenDNS"
	echo "  6) Google"
	read -rp "DNS [3]: " DNS
	DNS="${DNS:-3}"

	echo "Certificate type:"
	echo "  1) ECDSA prime256v1"
	echo "  2) RSA 3072-bit"
	read -rp "Certificate type [1]: " CERT_TYPE
	CERT_TYPE="${CERT_TYPE:-1}"

	read -rp "First client name [client]: " CLIENT
	CLIENT="${CLIENT:-client}"

	echo "Client key:"
	echo "  1) Passwordless"
	echo "  2) Password-protected"
	read -rp "Client key option [1]: " PASS
	PASS="${PASS:-1}"

	echo
	read -n1 -r -p "Press any key to begin installation..."
	echo
}

install_easyrsa() {
	rm -rf "${EASYRSA_DIR}"
	wget -q -O "/tmp/EasyRSA-${EASYRSA_VERSION}.tgz" \
		"https://github.com/OpenVPN/easy-rsa/releases/download/v${EASYRSA_VERSION}/EasyRSA-${EASYRSA_VERSION}.tgz"

	tar xzf "/tmp/EasyRSA-${EASYRSA_VERSION}.tgz" -C /tmp
	mv "/tmp/EasyRSA-${EASYRSA_VERSION}" "${EASYRSA_DIR}"
	chown -R root:root "${EASYRSA_DIR}"
	rm -f "/tmp/EasyRSA-${EASYRSA_VERSION}.tgz"
}

generate_pki() {
	cd "${EASYRSA_DIR}"

	if [[ "${CERT_TYPE}" == "2" ]]; then
		cat > vars <<EOF
set_var EASYRSA_KEY_SIZE 3072
set_var EASYRSA_REQ_CN "${SERVER_CN}"
EOF
	else
		cat > vars <<EOF
set_var EASYRSA_ALGO ec
set_var EASYRSA_CURVE prime256v1
set_var EASYRSA_REQ_CN "${SERVER_CN}"
EOF
	fi

	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa --batch build-server-full "${SERVER_NAME}" nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

	openvpn --genkey secret "${OPENVPN_DIR}/tls-crypt.key"

	cp "${PKI_DIR}/ca.crt" "${OPENVPN_DIR}/ca.crt"
	cp "${PKI_DIR}/issued/${SERVER_NAME}.crt" "${SERVER_DIR}/${SERVER_NAME}.crt"
	cp "${PKI_DIR}/private/${SERVER_NAME}.key" "${SERVER_DIR}/${SERVER_NAME}.key"
	cp "${PKI_DIR}/crl.pem" "${OPENVPN_DIR}/crl.pem"
	chmod 644 "${OPENVPN_DIR}/crl.pem"
}

write_server_conf() {
	mkdir -p "${SERVER_DIR}" "${LOG_DIR}"

	local group_name="nogroup"
	if ! grep -q "^nogroup:" /etc/group; then
		group_name="nobody"
	fi

	cat > "${SERVER_CONF}" <<EOF
port ${PORT}
proto ${PROTOCOL}4
dev tun

user nobody
group ${group_name}
persist-key
persist-tun

topology subnet
server ${VPN_SUBNET} ${VPN_NETMASK}
ifconfig-pool-persist ipp.txt

keepalive 10 120

ca ${OPENVPN_DIR}/ca.crt
cert ${SERVER_DIR}/${SERVER_NAME}.crt
key ${SERVER_DIR}/${SERVER_NAME}.key
crl-verify ${OPENVPN_DIR}/crl.pem

dh none
ecdh-curve prime256v1

tls-crypt ${OPENVPN_DIR}/tls-crypt.key
tls-version-min 1.2
remote-cert-tls client

auth SHA256
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-GCM

push "redirect-gateway def1 bypass-dhcp"
EOF

	case "${DNS}" in
		1)
			local resolv_conf="/etc/resolv.conf"
			if grep -q "127.0.0.53" /etc/resolv.conf && [[ -f /run/systemd/resolve/resolv.conf ]]; then
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			awk '/^nameserver / {print $2}' "${resolv_conf}" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | while read -r ns; do
				echo "push \"dhcp-option DNS ${ns}\"" >> "${SERVER_CONF}"
			done
			;;
		2)
			echo "push \"dhcp-option DNS ${VPN_DNS_IP}\"" >> "${SERVER_CONF}"
			;;
		3)
			echo 'push "dhcp-option DNS 1.1.1.1"' >> "${SERVER_CONF}"
			echo 'push "dhcp-option DNS 1.0.0.1"' >> "${SERVER_CONF}"
			;;
		4)
			echo 'push "dhcp-option DNS 9.9.9.9"' >> "${SERVER_CONF}"
			echo 'push "dhcp-option DNS 149.112.112.112"' >> "${SERVER_CONF}"
			;;
		5)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> "${SERVER_CONF}"
			echo 'push "dhcp-option DNS 208.67.220.220"' >> "${SERVER_CONF}"
			;;
		6)
			echo 'push "dhcp-option DNS 8.8.8.8"' >> "${SERVER_CONF}"
			echo 'push "dhcp-option DNS 8.8.4.4"' >> "${SERVER_CONF}"
			;;
	esac

	cat >> "${SERVER_CONF}" <<EOF

status ${LOG_DIR}/status.log
verb 3
explicit-exit-notify 1
EOF

	if [[ "${PROTOCOL}" == "tcp" ]]; then
		sed -i '/explicit-exit-notify/d' "${SERVER_CONF}"
	fi
}

enable_forwarding() {
	cat > /etc/sysctl.d/20-openvpn.conf <<EOF
net.ipv4.ip_forward=1
EOF
	sysctl --system >/dev/null
}

setup_firewall() {
	NIC="$(detect_nic)"

	mkdir -p /etc/iptables

	cat > /etc/iptables/add-openvpn-rules.sh <<EOF
#!/bin/sh
iptables -t nat -C POSTROUTING -s ${VPN_CIDR} -o ${NIC} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s ${VPN_CIDR} -o ${NIC} -j MASQUERADE
iptables -C INPUT -i tun0 -j ACCEPT 2>/dev/null || iptables -A INPUT -i tun0 -j ACCEPT
iptables -C FORWARD -i ${NIC} -o tun0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i ${NIC} -o tun0 -j ACCEPT
iptables -C FORWARD -i tun0 -o ${NIC} -j ACCEPT 2>/dev/null || iptables -A FORWARD -i tun0 -o ${NIC} -j ACCEPT
iptables -C INPUT -i ${NIC} -p ${PROTOCOL} --dport ${PORT} -j ACCEPT 2>/dev/null || iptables -A INPUT -i ${NIC} -p ${PROTOCOL} --dport ${PORT} -j ACCEPT
EOF

	cat > /etc/iptables/rm-openvpn-rules.sh <<EOF
#!/bin/sh
iptables -t nat -D POSTROUTING -s ${VPN_CIDR} -o ${NIC} -j MASQUERADE 2>/dev/null || true
iptables -D INPUT -i tun0 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i ${NIC} -o tun0 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i tun0 -o ${NIC} -j ACCEPT 2>/dev/null || true
iptables -D INPUT -i ${NIC} -p ${PROTOCOL} --dport ${PORT} -j ACCEPT 2>/dev/null || true
EOF

	chmod +x /etc/iptables/add-openvpn-rules.sh /etc/iptables/rm-openvpn-rules.sh

	cat > /etc/systemd/system/iptables-openvpn.service <<EOF
[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

	systemctl daemon-reload
	systemctl enable --now iptables-openvpn
}

write_client_template() {
	cat > "${CLIENT_TEMPLATE}" <<EOF
client
dev tun
proto ${CLIENT_PROTO}
remote ${ENDPOINT} ${PORT}
resolv-retry infinite
nobind
persist-key
persist-tun

remote-cert-tls server
verify-x509-name ${SERVER_NAME} name

auth SHA256
auth-nocache
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-GCM

tls-client
tls-version-min 1.2

setenv opt block-outside-dns
verb 3
EOF
}

new_client() {
	echo
	read -rp "Client name: " CLIENT

	until [[ "${CLIENT}" =~ ^[A-Za-z0-9_-]+$ ]]; do
		read -rp "Use only letters, numbers, underscore, or dash. Client name: " CLIENT
	done

	echo "Client key:"
	echo "  1) Passwordless"
	echo "  2) Password-protected"
	read -rp "Client key option [1]: " PASS
	PASS="${PASS:-1}"

	cd "${EASYRSA_DIR}"

	if [[ "${PASS}" == "2" ]]; then
		./easyrsa build-client-full "${CLIENT}"
	else
		./easyrsa build-client-full "${CLIENT}" nopass
	fi

	if [[ -n "${SUDO_USER:-}" && -d "/home/${SUDO_USER}" ]]; then
		home_dir="/home/${SUDO_USER}"
	else
		home_dir="/root"
	fi

	cp "${CLIENT_TEMPLATE}" "${home_dir}/${CLIENT}.ovpn"

	{
		echo "<ca>"
		cat "${PKI_DIR}/ca.crt"
		echo "</ca>"

		echo "<cert>"
		awk '/BEGIN/,/END/' "${PKI_DIR}/issued/${CLIENT}.crt"
		echo "</cert>"

		echo "<key>"
		cat "${PKI_DIR}/private/${CLIENT}.key"
		echo "</key>"

		echo "<tls-crypt>"
		cat "${OPENVPN_DIR}/tls-crypt.key"
		echo "</tls-crypt>"
	} >> "${home_dir}/${CLIENT}.ovpn"

	chmod 600 "${home_dir}/${CLIENT}.ovpn"

	echo
	echo "Client profile created: ${home_dir}/${CLIENT}.ovpn"
}

revoke_client() {
	if [[ ! -f "${PKI_DIR}/index.txt" ]]; then
		echo "No PKI found."
		exit 1
	fi

	local count
	count="$(tail -n +2 "${PKI_DIR}/index.txt" | grep -c "^V" || true)"

	if [[ "${count}" == "0" ]]; then
		echo "There are no active clients."
		exit 1
	fi

	echo
	echo "Select a client to revoke:"
	tail -n +2 "${PKI_DIR}/index.txt" | grep "^V" | cut -d '=' -f 2 | nl -s ') '

	read -rp "Client number: " CLIENT_NUM

	CLIENT="$(tail -n +2 "${PKI_DIR}/index.txt" | grep "^V" | cut -d '=' -f 2 | sed -n "${CLIENT_NUM}p")"

	if [[ -z "${CLIENT}" ]]; then
		echo "Invalid selection."
		exit 1
	fi

	cd "${EASYRSA_DIR}"
	./easyrsa --batch revoke "${CLIENT}"
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

	cp "${PKI_DIR}/crl.pem" "${OPENVPN_DIR}/crl.pem"
	chmod 644 "${OPENVPN_DIR}/crl.pem"

	rm -f "${PKI_DIR}/reqs/${CLIENT}.req"
	rm -f "${PKI_DIR}/private/${CLIENT}.key"
	rm -f "${PKI_DIR}/issued/${CLIENT}.crt"
	find /home/ -maxdepth 2 -name "${CLIENT}.ovpn" -delete 2>/dev/null || true
	rm -f "/root/${CLIENT}.ovpn"

	systemctl restart openvpn-server@server

	echo "Client revoked: ${CLIENT}"
}

remove_openvpn() {
	read -rp "Confirm removal of OpenVPN? [y/N]: " REMOVE
	REMOVE="${REMOVE:-n}"

	if [[ "${REMOVE}" != "y" && "${REMOVE}" != "Y" ]]; then
		echo "Removal aborted."
		exit 0
	fi

	systemctl disable --now openvpn-server@server 2>/dev/null || true
	systemctl disable --now iptables-openvpn 2>/dev/null || true

	rm -f /etc/systemd/system/iptables-openvpn.service
	rm -f /etc/iptables/add-openvpn-rules.sh
	rm -f /etc/iptables/rm-openvpn-rules.sh
	systemctl daemon-reload

	case "${OS_FAMILY}" in
		debian)
			apt-get autoremove --purge -y openvpn
			;;
		fedora|rhel)
			dnf remove -y openvpn || yum remove -y openvpn
			;;
		arch)
			pacman --noconfirm -R openvpn
			;;
	esac

	find /home/ -maxdepth 2 -name "*.ovpn" -delete 2>/dev/null || true
	find /root/ -maxdepth 1 -name "*.ovpn" -delete 2>/dev/null || true

	rm -rf "${OPENVPN_DIR}"
	rm -rf "${LOG_DIR}"
	rm -f /etc/sysctl.d/20-openvpn.conf

	sysctl --system >/dev/null || true

	echo "OpenVPN removed."
}

install_openvpn() {
	install_questions
	install_packages

	if [[ "${DNS}" == "2" ]]; then
		install_unbound
	fi

	SERVER_CN="cn_$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16)"
	SERVER_NAME="server_$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16)"

	mkdir -p "${OPENVPN_DIR}" "${SERVER_DIR}" "${LOG_DIR}"

	install_easyrsa
	generate_pki
	write_server_conf
	enable_forwarding
	setup_firewall
	write_client_template

	systemctl enable --now openvpn-server@server

	new_client

	echo
	echo "OpenVPN installation complete."
	echo "To add or revoke clients, run this script again."
}

manage_menu() {
	echo "OpenVPN appears to already be installed."
	echo
	echo "What do you want to do?"
	echo "  1) Add a new client profile"
	echo "  2) Revoke an existing client certificate"
	echo "  3) Remove OpenVPN"
	echo "  4) Exit"
	read -rp "Select an option [1-4]: " MENU_OPTION

	case "${MENU_OPTION}" in
		1)
			new_client
			;;
		2)
			revoke_client
			;;
		3)
			remove_openvpn
			;;
		4)
			exit 0
			;;
		*)
			echo "Invalid option."
			exit 1
			;;
	esac
}

initial_check

if [[ -f "${SERVER_CONF}" ]]; then
	manage_menu
else
	install_openvpn
fi
