#!/bin/bash

# OpenVPN server installer for Debian, CentOS, Fedora, Ubuntu, and Arch Linux
# https://github.com/benmshapiro/openvpn-rapid

function ISroot () {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function TUNcheck () {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkOp () {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		source /etc/os-release

		if [[ "$ID" == "debian" ]]; then
			if [[ ! $VERSION_ID =~ (8|9|10) ]]; then
				echo "Your version of Debian is not supported."
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ "$CONTINUE" = "n" ]]; then
					exit 1
				fi
			fi
		elif [[ "$ID" == "ubuntu" ]];then
			OS="ubuntu"
			if [[ ! $VERSION_ID =~ (16.04|18.04|19.04) ]]; then
				echo "Your version of Ubuntu is not supported."
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ "$CONTINUE" = "n" ]]; then
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/fedora-release ]]; then
		OS=fedora
	elif [[ -e /etc/centos-release ]]; then
		if ! grep -qs "^CentOS Linux release 7" /etc/centos-release; then
			echo "Your version of CentOS is not supported."
			unset CONTINUE
			until [[ $CONTINUE =~ (y|n) ]]; do
				read -rp "Continue anyway? [y/n]: " -e CONTINUE
			done
			if [[ "$CONTINUE" = "n" ]]; then
				echo "byyyeeee!!!"
				exit 1
			fi
		fi
		OS=centos
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "You are not running this installer on a Debian, Fedora, CentOS, Ubuntu or Arch Linux system"
		exit 1
	fi
}

function initialCheck () {
	if ! ISroot; then
		echo "Sorry, we need root access to run this..."
		exit 1
	fi
	if ! TUNcheck; then
		echo "TUN is not available"
		exit 1
	fi
	checkOp
}

function setUnbound () {
	if [[ ! -e /etc/unbound/unbound.conf ]]; then

		if [[ "$OS" =~ (debian|ubuntu) ]]; then
			apt-get install -y unbound

			# Debian Configuration
			echo "interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes" >> /etc/unbound/unbound.conf

		elif [[ "$OS" = "centos" ]]; then
			yum install -y unbound

			# CentOS Configuration
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf

		elif [[ "$OS" = "fedora" ]]; then
			dnf install -y unbound

			# Fedroa Configuration
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf

		elif [[ "$OS" = "arch" ]]; then
			pacman -Syu --noconfirm unbound
			# Get root servers list
			curl -o /etc/unbound/root.hints https://www.internic.net/domain/named.cache

			mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.old

			echo "server:
	use-syslog: no
	do-daemonize: no
	username: "unbound"
	directory: "/etc/unbound"
	trust-anchor-file: trusted-key.key
	root-hints: root.hints
	interface: 10.8.0.1
	access-control: 10.8.0.1/24 allow
	port: 53
	num-threads: 2
	use-caps-for-id: yes
	harden-glue: yes
	hide-identity: yes
	hide-version: yes
	qname-minimisation: yes
	prefetch: yes" > /etc/unbound/unbound.conf
		fi

		if [[ ! "$OS" =~ (fedora|centos) ]];then
			# DNS Rebinding fix
			echo "private-address: 10.0.0.0/8
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: 127.0.0.0/8" >> /etc/unbound/unbound.conf
		fi
	else # If Unbound is already installed
		echo "include: /etc/unbound/openvpn.conf" >> /etc/unbound/unbound.conf

		# Add Unbound 'server' for the OpenVPN subnet
		echo "server:
interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes
private-address: 10.0.0.0/8
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: 127.0.0.0/8" > /etc/unbound/openvpn.conf
	fi

		systemctl enable unbound
		systemctl restart unbound
}

function installQuestions () {
	echo "Welcome to the Rapid OpenVPN installer!"
	echo "The git repository is available at: https://github.com/benmshapiro/openvpn-rapid"
	echo ""
	echo "You need to answer a few questions before starting the installation."
	echo "To use default options, just press 'enter' if you are ok with them."
	echo ""
	echo "You need to know the IPv4 address of the network interface you want OpenVPN listening to."
	echo "Unless your server is behind NAT, it should be your public IPv4 address."


	# Detect public IPv4 address and pre-fill for the user.
	IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
	APPROVE_IP=${APPROVE_IP:-n}
	if [[ $APPROVE_IP =~ n ]]; then
		read -rp "IPv4 address: " -e -i "$IP" IP
	fi

	# If private IP address, the server must be behind NAT.
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo ""
		echo "This server is behind NAT. What is its public IPv4 address?"
		until [[ "$ENDPOINT" != "" ]]; do
			read -rp "Public IPv4 address or hostname: " -e ENDPOINT
		done
	fi

	# OpenVPN port options
	echo ""
	echo "What port do you want OpenVPN to listen to?"
	echo "   1) Default: 1194"
	echo "   2) Custom port"
	echo "   3) Random port [49152-65535]"
	until [[ "$PORT_CHOICE" =~ ^[1-3]$ ]]; do
		read -rp "Port choice [1-3]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
		1)
			PORT="1194"
		;;
		2)
			until [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
				read -rp "Custom port [1-65535]: " -e -i 1194 PORT
			done
		;;
		3)
			PORT=$(shuf -i49152-65535 -n1) # Generates random number within private ports range
			echo "Random Port: $PORT"
		;;

	# OpenVPN protocol
	echo ""
	echo "What protocol do you want OpenVPN to use?"
	echo "UDP is prefered. Unless it is not available, you shouldn't use TCP."
	echo "   1) UDP"
	echo "   2) TCP"

	# DNS resolver options
	echo ""
	echo "What DNS provider do you want to use with OpenVPN?"
	echo "   1) Current system resolvers (from /etc/resolv.conf)"
	echo "   2) Self-hosted DNS Resolver (Unbound)"
	echo "   3) Cloudflare"
	echo "   4) Quad9"
	echo "   5) Quad9 uncensored"
	echo "   6) OpenDNS"
	echo "   7) Google"

	# Compression options
	echo ""
	echo "Do you want to use compression?"
	echo ""
	echo "   1) LZ4-v2"
	echo "   2) LZ4"
	echo "   3) LZ0"


	# Encyption options
	echo ""
	echo "Do you want to customize encryption settings?"
	echo "Unless you know what you're doing, you should stick with the default parameters provided by the script."
	echo ""

	echo ""
	echo "Choose which cipher you want to use for the data channel:"
	echo "   1) AES-128-GCM (default)"
	echo "   2) AES-192-GCM"
	echo "   3) AES-256-GCM"
	echo "   4) AES-128-CBC"
	echo "   5) AES-192-CBC"
	echo "   6) AES-256-CBC"

	echo ""
	echo "Choose a type of certificate to use:"
	echo "   1) ECDSA (default)"
	echo "   2) RSA"

	echo ""
	echo "Choose which cipher you want to use for the control channel:"
	echo "   1) ECDHE-ECDSA-AES-128-GCM-SHA256 (recommended)"
	echo "   2) ECDHE-ECDSA-AES-256-GCM-SHA384"


	echo ""
	echo "Choose what kind of Diffie-Hellman key you want to use:"
	echo "   1) ECDH (recommended)"
	echo "   2) DH"

	echo "Which digest algorithm do you want to use for HMAC?"
	echo "   1) SHA-256 (recommended)"
	echo "   2) SHA-384"
	echo "   3) SHA-512"

	echo ""
	echo "You can add an additional layer of security to the control channel with tls-auth and tls-crypt"
	echo "tls-auth authenticates the packets, while tls-crypt authenticate and encrypt them."
	echo "   1) tls-crypt (recommended)"
	echo "   2) tls-auth"
	
	echo ""
	echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now."
	echo "You will be able to generate a client at the end of the installation."

	# Finalize setup
	echo ""
	echo "Okay, you are ready to setup your OpenVPN server now."
	echo "You will be able to generate a client at the end of the installation."

	}

	function newClient () {

	}