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
	esac

	# OpenVPN protocol
	echo ""
	echo "What protocol do you want OpenVPN to use?"
	echo "   1) UDP (faster, default)"
	echo "   2) TCP"
		until [[ "$PROTOCOL_CHOICE" =~ ^[1-2]$ ]]; do
		read -rp "Protocol [1-2]: " -e -i 1 PROTOCOL_CHOICE
	done
	case $PROTOCOL_CHOICE in
		1)
			PROTOCOL="udp"
		;;
		2)
			PROTOCOL="tcp"
		;;
	esac

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
	until [[ "$DNS" =~ ^[0-9]+$ ]] && [ "$DNS" -ge 1 ]; do
		read -rp "DNS [1-7]: " -e -i 3 DNS
			if [[ $DNS == 2 ]] && [[ -e /etc/unbound/unbound.conf ]]; then
				echo ""
				echo "Unbound is already installed."
				echo "You can allow the script to configure it in order to use it from your OpenVPN clients"
				echo "The script will add a second server to '/etc/unbound/unbound.conf' for the OpenVPN subnet."
				echo ""

				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Apply configuration changes to Unbound? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE = "n" ]];then
					# Break the loop
					unset DNS
					unset CONTINUE
				fi
			fi
	done

	# Compression options
	echo ""
	echo "Do you want to use compression?"
	until [[ $COMPRESSION_ENABLED =~ (y|n) ]]; do
		read -rp"Enable compression? [y/n]: " -e -i n COMPRESSION_ENABLED
	done
	if [[ $COMPRESSION_ENABLED == "y" ]];then
	echo "Choose which algorithm to use:"
	echo "   1) LZ4-v2"
	echo "   2) LZ4"
	echo "   3) LZ0"
	until [[ $COMPRESSION_CHOICE =~ ^[1-3]$ ]]; do
			read -rp"Compression algorithm [1-3]: " -e -i 1 COMPRESSION_CHOICE
		done
		case $COMPRESSION_CHOICE in
			1)
			COMPRESSION_ALG="lz4-v2"
			;;
			2)
			COMPRESSION_ALG="lz4"
			;;
			3)
			COMPRESSION_ALG="lzo"
			;;
		esac
	fi

	# Encryption options
	echo ""
	echo "Do you want to customize encryption settings?"
	echo "Not sure? Stick with the default parameters provided by the script."
	echo ""
	until [[ $CUSTOMIZE_ENC =~ (y|n) ]]; do
		read -rp "Change encryption settings? [y/n]: " -e -i n CUSTOMIZE_ENC
	done
	if [[ $CUSTOMIZE_ENC == "n" ]];then
		# Use default, sane and fast parameters
		CIPHER="AES-128-GCM"
		CERT_TYPE="1" # ECDSA
		CERT_CURVE="prime256v1"
		CTRL_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
		DH_TYPE="1" # ECDH
		DH_CURVE="prime256v1"
		HMAC_ALG="SHA256"
		TLS_SIG="1" # tls-crypt
	else
	
		echo ""
		echo "Choose which cipher you want to use for the data channel:"
		echo "   1) AES-128-GCM (default)"
		echo "   2) AES-192-GCM"
		echo "   3) AES-256-GCM"
		echo "   4) AES-128-CBC"
		echo "   5) AES-192-CBC"
		echo "   6) AES-256-CBC"
		until [[ "$CIPHER_CHOICE" =~ ^[1-6]$ ]]; do
				read -rp "Cipher [1-6]: " -e -i 1 CIPHER_CHOICE
		done
		case $CIPHER_CHOICE in
			1)
				CIPHER="AES-128-GCM"
			;;
			2)
				CIPHER="AES-192-GCM"
			;;
			3)
				CIPHER="AES-256-GCM"
			;;
			4)
				IPHER="AES-128-CBC"
			;;
			5)
				CIPHER="AES-192-CBC"
			;;
			6)
				CIPHER="AES-256-CBC"
			;;
		esac

		echo ""
		echo "Choose a type of certificate to use:"
		echo "   1) ECDSA (default)"
		echo "   2) RSA"
		until [[ $CERT_TYPE =~ ^[1-2]$ ]]; do
				read -rp"Certificate key type [1-2]: " -e -i 1 CERT_TYPE
		done
		case $CERT_TYPE in
			1)
				echo ""
				echo "Choose which curve you want to use for the certificate's key:"
				echo "   1) prime256v1 (recommended)"
				echo "   2) secp384r1"
				echo "   3) secp521r1"
				until [[ $CERT_CURVE_CHOICE =~ ^[1-3]$ ]]; do
					read -rp"Curve [1-3]: " -e -i 1 CERT_CURVE_CHOICE
				done
				case $CERT_CURVE_CHOICE in
					1)
						CERT_CURVE="prime256v1"
					;;
					2)
						CERT_CURVE="secp384r1"
					;;
					3)
						CERT_CURVE="secp521r1"
					;;
				esac
				;;
			2)
				echo ""
				echo "Choose which size you want to use for the certificate's RSA key:"
				echo "   1) 2048 bits (recommended)"
				echo "   2) 3072 bits"
				echo "   3) 4096 bits"
				until [[ "$RSA_KEY_SIZE_CHOICE" =~ ^[1-3]$ ]]; do
					read -rp "RSA key size [1-3]: " -e -i 1 RSA_KEY_SIZE_CHOICE
				done
				case $RSA_KEY_SIZE_CHOICE in
					1)
						RSA_KEY_SIZE="2048"
					;;
					2)
						RSA_KEY_SIZE="3072"
					;;
					3)
						RSA_KEY_SIZE="4096"
					;;
				esac
			;;
		esac

		echo ""
		echo "Choose which cipher you want to use for the control channel:"
		echo "   1) ECDHE-ECDSA-AES-128-GCM-SHA256 (recommended)"
		echo "   2) ECDHE-ECDSA-AES-256-GCM-SHA384"
		case $CERT_TYPE in
			1)
				echo "   1) ECDHE-ECDSA-AES-128-GCM-SHA256 (recommended)"
				echo "   2) ECDHE-ECDSA-AES-256-GCM-SHA384"
				until [[ $CTRL_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
					read -rp"Control channel cipher [1-2]: " -e -i 1 CTRL_CIPHER_CHOICE
				done
				case $CTRL_CIPHER_CHOICE in
					1)
						CTRL_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
					;;
					2)
						CTRL_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
					;;
				esac
			;;
			2)
				echo "   1) ECDHE-RSA-AES-128-GCM-SHA256 (recommended)"
				echo "   2) ECDHE-RSA-AES-256-GCM-SHA384"
				until [[ $CTRL_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
					read -rp"Control channel cipher [1-2]: " -e -i 1 CTRL_CIPHER_CHOICE
				done
				case $CTRL_CIPHER_CHOICE in
					1)
						CTRL_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
					;;
					2)
						CTRL_CIPHER="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
					;;
				esac
			;;
		esac

		echo ""
		echo "Choose what kind of Diffie-Hellman key you want to use:"
		echo "   1) ECDH (recommended)"
		echo "   2) DH"
		until [[ $DH_TYPE =~ [1-2] ]]; do
				read -rp"DH key type [1-2]: " -e -i 1 DH_TYPE
		done
		case $DH_TYPE in
			1)
				echo ""
				echo "Choose which curve you want to use for the ECDH key:"
				echo "   1) prime256v1 (recommended)"
				echo "   2) secp384r1"
				echo "   3) secp521r1"
				while [[ $DH_CURVE_CHOICE != "1" && $DH_CURVE_CHOICE != "2" && $DH_CURVE_CHOICE != "3" ]]; do
					read -rp"Curve [1-3]: " -e -i 1 DH_CURVE_CHOICE
				done
				case $DH_CURVE_CHOICE in
					1)
						DH_CURVE="prime256v1"
					;;
					2)
						DH_CURVE="secp384r1"
					;;
					3)
						DH_CURVE="secp521r1"
					;;
				esac
			;;
			2)
				echo ""
				echo "Choose what size of DH key you want to use:"
				echo "   1) 2048 bits (recommended)"
				echo "   2) 3072 bits"
				echo "   3) 4096 bits"
				until [[ "$DH_KEY_SIZE_CHOICE" =~ ^[1-3]$ ]]; do
					read -rp "DH key size [1-3]: " -e -i 1 DH_KEY_SIZE_CHOICE
				done
				case $DH_KEY_SIZE_CHOICE in
					1)
						DH_KEY_SIZE="2048"
					;;
					2)
						DH_KEY_SIZE="3072"
					;;
					3)
						DH_KEY_SIZE="4096"
					;;
				esac
			;;
		esac

		echo "Which digest algorithm do you want to use for HMAC?"
		echo "   1) SHA-256 (recommended)"
		echo "   2) SHA-384"
		echo "   3) SHA-512"
		until [[ $HMAC_ALG_CHOICE =~ ^[1-3]$ ]]; do
			read -rp "Digest algorithm [1-3]: " -e -i 1 HMAC_ALG_CHOICE
		done
		case $HMAC_ALG_CHOICE in
			1)
				HMAC_ALG="SHA256"
			;;
			2)
				HMAC_ALG="SHA384"
			;;
			3)
				HMAC_ALG="SHA512"
			;;
		esac

		echo ""
		echo "You can add an additional layer of security to the control channel with tls-auth and tls-crypt"
		echo "tls-auth authenticates the packets, while tls-crypt authenticate and encrypt them."
		echo "   1) tls-crypt (recommended)"
		echo "   2) tls-auth"
		until [[ $TLS_SIG =~ [1-2] ]]; do
				read -rp "Control channel additional security mechanism [1-2]: " -e -i 1 TLS_SIG
		done
	fi
	
# Finalize setup
echo ""
echo "Okay, you are ready to setup your OpenVPN server now."
echo "You will be able to generate a client at the end of the installation."
APPROVE_INSTALL=${APPROVE_INSTALL:-n}
if [[ $APPROVE_INSTALL =~ n ]]; then
	read -n1 -r -p "Press any key to continue..."
fi
}

function installOpenVPN () {
	if [[ $AUTO_INSTALL == "y" ]]; then
		# Set default parameters.
		APPROVE_INSTALL=${APPROVE_INSTALL:-y}
		APPROVE_IP=${APPROVE_IP:-y}
		PORT_CHOICE=${PORT_CHOICE:-1}
		PROTOCOL_CHOICE=${PROTOCOL_CHOICE:-1}
		DNS=${DNS:-1}
		COMPRESSION_ENABLED=${COMPRESSION_ENABLED:-n}
		CUSTOMIZE_ENC=${CUSTOMIZE_ENC:-n}
		CLIENT=${CLIENT:-client}
		PASS=${PASS:-1}
		CONTINUE=${CONTINUE:-y}

		# If behind NAT, default to the public IPv4.
		PUBLIC_IPV4=$(curl ifconfig.co)
		ENDPOINT=${ENDPOINT:-$PUBLIC_IPV4}
	fi

	# Run installQuestions() first, then set other variables if auto-install
	installQuestions

	# Get the public-facing interface from the default route
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

	if [[ "$OS" =~ (debian|ubuntu) ]]; then
		apt-get update
		apt-get -y install ca-certificates gnupg
		
		# Add the OpenVPN repo for latest version.
		if [[ "$VERSION_ID" = "8" ]]; then
			echo "deb http://build.openvpn.net/debian/openvpn/stable jessie main" > /etc/apt/sources.list.d/openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt-get update
		fi
		if [[ "$VERSION_ID" = "16.04" ]]; then
			echo "deb http://build.openvpn.net/debian/openvpn/stable xenial main" > /etc/apt/sources.list.d/openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt-get update
		fi
		
		# Ubuntu > v.16.04 and Debian > v.8 have OpenVPN >= 2.4 without the need of a third party repository.
		apt-get install -y openvpn iptables openssl wget ca-certificates curl
	elif [[ "$OS" = 'centos' ]]; then
		yum install -y epel-release
		yum install -y openvpn iptables openssl wget ca-certificates curl
	elif [[ "$OS" = 'fedora' ]]; then
		dnf install -y openvpn iptables openssl wget ca-certificates curl
	elif [[ "$OS" = 'arch' ]]; then
		
		# Install required dependencies and upgrade the system
		pacman --needed --noconfirm -Syu openvpn iptables openssl wget ca-certificates curl
	fi

	# Search nogroup or nobody for the servers permissionless group
	if grep -qs "^nogroup:" /etc/group; then
		NOGROUP=nogroup
	else
		NOGROUP=nobody
	fi

	# Find if am old version of easy-rsa was default in openvpn packages
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi

	# Install the latest version of easy-rsa from source (github repo)
	local version="3.0.6"
	wget -O ~/EasyRSA-unix-v${version}.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-unix-v${version}.tgz
	tar xzf ~/EasyRSA-unix-v${version}.tgz -C ~/
	mv ~/EasyRSA-v${version} /etc/openvpn/easy-rsa
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -f ~/EasyRSA-unix-v${version}.tgz

	cd /etc/openvpn/easy-rsa/
	case $CERT_TYPE in
		1)
			echo "set_var EASYRSA_ALGO ec" > vars
			echo "set_var EASYRSA_CURVE $CERT_CURVE" >> vars
		;;
		2)
			echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" > vars
		;;
	esac

	# Generate a random, alphanumeric identifier of 16 characters for CN and one for server name
	SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
	SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
	echo "set_var EASYRSA_REQ_CN $SERVER_CN" >> vars
	
	# Create the PKI, set up the CA, the DH params and the server certificate
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass

	if [[ $DH_TYPE == "2" ]]; then
		# ECDH keys are generated on-the-fly so we don't need to generate them beforehand
		openssl dhparam -out dh.pem $DH_KEY_SIZE
	fi

	./easyrsa build-server-full "$SERVER_NAME" nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

	case $TLS_SIG in
		1)
			# Generate tls-crypt key
			openvpn --genkey --secret /etc/openvpn/tls-crypt.key
		;;
		2)
			# Generate tls-auth key
			openvpn --genkey --secret /etc/openvpn/tls-auth.key
		;;
	esac

	# Copy all the generated files to new destination directory
	cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	if [[ $DH_TYPE == "2" ]]; then
		cp dh.pem /etc/openvpn
	fi

	# Change cert revoke list permissions to readable for non-root
	chmod 644 /etc/openvpn/crl.pem

	# Generate server.conf file
	echo "port $PORT" > /etc/openvpn/server.conf
	if [[ "$IPV6_SUPPORT" = 'n' ]]; then
		echo "proto $PROTOCOL" >> /etc/openvpn/server.conf
	elif [[ "$IPV6_SUPPORT" = 'y' ]]; then
		echo "proto ${PROTOCOL}6" >> /etc/openvpn/server.conf
	fi

	echo "dev tun
user nobody
group $NOGROUP
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" >> /etc/openvpn/server.conf

	# DNS resolvers
	case $DNS in
		1)
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep -q "127.0.0.53" "/etc/resolv.conf"; then
				RESOLVCONF='/run/systemd/resolve/resolv.conf'
			else
				RESOLVCONF='/etc/resolv.conf'
			fi
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read -r line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
			done
		;;
		2)
			echo 'push "dhcp-option DNS 10.8.0.1"' >> /etc/openvpn/server.conf
		;;
		3) # Cloudflare
			echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server.conf
		;;
		4) # Quad9
			echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server.conf
		;;
		5) # Quad9 uncensored
			echo 'push "dhcp-option DNS 9.9.9.10"' >> /etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 149.112.112.10"' >> /etc/openvpn/server.conf
		;;
		6) # OpenDNS
			echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
		;;
		7) # Google
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
	esac
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf

	if [[ $COMPRESSION_ENABLED == "y"  ]]; then
		echo "compress $COMPRESSION_ALG" >> /etc/openvpn/server.conf
	fi

	if [[ $DH_TYPE == "1" ]]; then
		echo "dh none" >> /etc/openvpn/server.conf
		echo "ecdh-curve $DH_CURVE" >> /etc/openvpn/server.conf
	elif [[ $DH_TYPE == "2" ]]; then
		echo "dh dh.pem" >> /etc/openvpn/server.conf
	fi

	case $TLS_SIG in
		1)
			echo "tls-crypt tls-crypt.key 0" >> /etc/openvpn/server.conf
		;;
		2)
			echo "tls-auth tls-auth.key 0" >> /etc/openvpn/server.conf
		;;
	esac

	echo "crl-verify crl.pem
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min 1.2
tls-cipher $CTRL_CIPHER
status /var/log/openvpn/status.log
verb 3" >> /etc/openvpn/server.conf

	# Create log dir
	mkdir -p /var/log/openvpn

	# Enable routing
	echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.d/20-openvpn.conf
	
	# Avoid an unneeded reboot
	sysctl --system

	# Finally, restart and enable OpenVPN
	if [[ "$OS" = 'arch' || "$OS" = 'fedora' ]]; then
		# Don't modify package-provided service
		cp /usr/lib/systemd/system/openvpn-server@.service /etc/systemd/system/openvpn-server@.service

		if [[ "$OS" == "fedora" ]];then
			sed -i 's|--cipher AES-256-GCM --ncp-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC:BF-CBC||' /etc/systemd/system/openvpn-server@.service
		fi

		systemctl daemon-reload
		systemctl restart openvpn-server@server
		systemctl enable openvpn-server@server
	elif [[ "$OS" == "ubuntu" ]] && [[ "$VERSION_ID" == "16.04" ]]; then
		# On Ubuntu v.16.04, use the package from the OpenVPN repo
		systemctl enable openvpn
		systemctl start openvpn
	else
		# Don't modify package-provided service
		cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service

		systemctl daemon-reload
		systemctl restart openvpn@server
		systemctl enable openvpn@server
	fi

	if [[ $DNS == 2 ]];then
		installUnbound
	fi

	# Add iptables rules in two scripts
	mkdir /etc/iptables

	# Script to add rules for iptables
	echo "#!/bin/sh
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -A INPUT -i tun0 -j ACCEPT
iptables -A FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -A INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" > /etc/iptables/add-openvpn-rules.sh

	if [[ "$IPV6_SUPPORT" = 'y' ]]; then
		echo "ip6tables -t nat -A POSTROUTING -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -A INPUT -i tun0 -j ACCEPT
ip6tables -A FORWARD -i $NIC -o tun0 -j ACCEPT
ip6tables -A FORWARD -i tun0 -o $NIC -j ACCEPT" >> /etc/iptables/add-openvpn-rules.sh
	fi

	# Script to remove rules
	echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" > /etc/iptables/rm-openvpn-rules.sh

	if [[ "$IPV6_SUPPORT" = 'y' ]]; then
		echo "ip6tables -t nat -D POSTROUTING -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -D INPUT -i tun0 -j ACCEPT
ip6tables -D FORWARD -i $NIC -o tun0 -j ACCEPT
ip6tables -D FORWARD -i tun0 -o $NIC -j ACCEPT" >> /etc/iptables/rm-openvpn-rules.sh
	fi

	chmod +x /etc/iptables/add-openvpn-rules.sh
	chmod +x /etc/iptables/rm-openvpn-rules.sh

	# Handle the rules for iptabels via a systemd script
	echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/iptables-openvpn.service

	# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn

	# If the server is behind a NAT, use the correct IP address for the clients to connect to
	if [[ "$ENDPOINT" != "" ]]; then
		IP=$ENDPOINT
	fi

	# client-template.txt is created so we have a template to add further users later
	echo "client" > /etc/openvpn/client-template.txt
	if [[ "$PROTOCOL" = 'udp' ]]; then
		echo "proto udp" >> /etc/openvpn/client-template.txt
	elif [[ "$PROTOCOL" = 'tcp' ]]; then
		echo "proto tcp-client" >> /etc/openvpn/client-template.txt
	fi
	echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CTRL_CIPHER
setenv opt block-outside-dns # Prevent Windows 10 DNS leak
verb 3" >> /etc/openvpn/client-template.txt

if [[ $COMPRESSION_ENABLED == "y"  ]]; then
	echo "compress $COMPRESSION_ALG" >> /etc/openvpn/client-template.txt
fi

# Generate the custom client.ovpn
newClient
echo "If you want to add more clients you need to run this script another time!"
}

function newClient () {	
	echo ""
	echo "Pick a name for the client."
	echo "Use one word only, no spaces, no special characters."

	until [[ "$CLIENT" =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Client name: " -e CLIENT
	done

	echo ""
	echo "Do you want to protect this key with a password?"
	echo "   1) Add a passwordless client"
	echo "   2) Use a password for the client"

	until [[ "$PASS" =~ ^[1-2]$ ]]; do
		read -rp "Select an option [1-2]: " -e -i 1 PASS
	done

	cd /etc/openvpn/easy-rsa/ || return
	case $PASS in
		1)
			./easyrsa build-client-full "$CLIENT" nopass
		;;
		2)
		echo "You will be asked for the client password below"
			./easyrsa build-client-full "$CLIENT"
		;;
	esac

	# Home directory of the user is where the client configuration is written (.ovpn)
	if [ -e "/home/$CLIENT" ]; then  # if $1 is a username
		homeDir="/home/$CLIENT"
	elif [ "${SUDO_USER}" ]; then   # if not, use SUDO_USER
		homeDir="/home/${SUDO_USER}"
	else  # if not SUDO_USER, use /root
		homeDir="/root"
	fi

	# Determine is tls-auth or tls-crypt
	if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
		TLS_SIG="1"
	elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
		TLS_SIG="2"
	fi

	# Generates the client.ovpn
	cp /etc/openvpn/client-template.txt "$homeDir/$CLIENT.ovpn"
	{
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"

		echo "<cert>"
		awk '/BEGIN/,/END/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
		echo "</cert>"

		echo "<key>"
		cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
		echo "</key>"

		case $TLS_SIG in
			1)
				echo "<tls-crypt>"
				cat /etc/openvpn/tls-crypt.key
				echo "</tls-crypt>"
			;;
			2)
				echo "key-direction 1"
				echo "<tls-auth>"
				cat /etc/openvpn/tls-auth.key
				echo "</tls-auth>"
			;;
		esac
	} >> "$homeDir/$CLIENT.ovpn"

	echo ""
	echo "Client $CLIENT added, find the configuration at $homeDir/$CLIENT.ovpn."

	exit 0		
	}

function revokeClient () {
	NUMOFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ "$NUMOFCLIENTS" = '0' ]]; then
		echo ""
		echo "There are no existing clients!"
		exit 1
	fi

	echo ""
	echo "Select the existing client certificate you want to revoke"
	tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
	if [[ "$NUMOFCLIENTS" = '1' ]]; then
		read -rp "Select one client [1]: " CLIENTNUM
	else
		read -rp "Select one client [1-$NUMOFCLIENTS]: " CLIENTNUM
	fi

	CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUM"p)
	cd /etc/openvpn/easy-rsa/
	./easyrsa --batch revoke "$CLIENT"
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# Cleanup
	rm -f "pki/reqs/$CLIENT.req"
	rm -f "pki/private/$CLIENT.key"
	rm -f "pki/issued/$CLIENT.crt"
	rm -f /etc/openvpn/crl.pem
	cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
	chmod 644 /etc/openvpn/crl.pem
	find /home/ -maxdepth 2 -name "$CLIENT.ovpn" -delete
	rm -f "/root/$CLIENT.ovpn"
	sed -i "s|^$CLIENT,.*||" /etc/openvpn/ipp.txt

	echo ""
	echo "The certificate for client $CLIENT revoked."
}

function removeUnbound () {
	# Remove OpenVPN-related configurations.
	sed -i 's|include: \/etc\/unbound\/openvpn.conf||' /etc/unbound/unbound.conf
	rm /etc/unbound/openvpn.conf
	systemctl restart unbound

	until [[ $REMOVE_UNBOUND =~ (y|n) ]]; do
		echo ""
		echo "If Unbound was used before installing OpenVPN, only the configuration related to OpenVPN has been removed."
		read -rp "Do you want to completely remove Unbound? [y/n]: " -e REMOVE_UNBOUND
	done

	if [[ "$REMOVE_UNBOUND" = 'y' ]]; then
		
		# Stop Unbound service.
		systemctl stop unbound

		if [[ "$OS" =~ (debian|ubuntu) ]]; then
			apt-get autoremove --purge -y unbound
		elif [[ "$OS" = 'arch' ]]; then
			pacman --noconfirm -R unbound
		elif [[ "$OS" = 'centos' ]]; then
			yum remove -y unbound
		elif [[ "$OS" = 'fedora' ]]; then
			dnf remove -y unbound
		fi

		rm -rf /etc/unbound/

		echo ""
		echo "Unbound removal complete"
	else
		echo ""
		echo "Unbound still installed."
	fi
}

function removeOpenVPN () {
	echo ""
	read -rp "Comfirm the removal of OpenVPN? [y/n]: " -e -i n REMOVE
	if [[ "$REMOVE" = 'y' ]]; then
		
		# Get OpenVPN port from the configuration.
		PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)

		# Stop OpenVPN service.
		if [[ "$OS" =~ (fedora|arch) ]]; then
			systemctl disable openvpn-server@server
			systemctl stop openvpn-server@server
		elif [[ "$OS" == "ubuntu" ]] && [[ "$VERSION_ID" == "16.04" ]]; then
			systemctl disable openvpn
			systemctl stop openvpn
		else
			systemctl disable openvpn@server
			systemctl stop openvpn@server
		fi

		# Remove the iptables rules related to the script.
		systemctl stop iptables-openvpn
		# Cleanup files.
		systemctl disable iptables-openvpn
		rm /etc/systemd/system/iptables-openvpn.service
		systemctl daemon-reload
		rm /etc/iptables/add-openvpn-rules.sh
		rm /etc/iptables/rm-openvpn-rules.sh

		# Stop OpenVPN service.
		if [[ "$OS" =~ (debian|ubuntu) ]]; then
			apt-get autoremove --purge -y openvpn
			if [[ -e /etc/apt/sources.list.d/openvpn.list ]];then
				rm /etc/apt/sources.list.d/openvpn.list
				apt-get update
			fi
		elif [[ "$OS" = 'arch' ]]; then
			pacman --noconfirm -R openvpn
		elif [[ "$OS" = 'centos' ]]; then
			yum remove -y openvpn
		elif [[ "$OS" = 'fedora' ]]; then
			dnf remove -y openvpn
		fi

		# Cleanup
		find /home/ -maxdepth 2 -name "*.ovpn" -delete
		find /root/ -maxdepth 1 -name "*.ovpn" -delete
		rm -rf /etc/openvpn
		rm -rf /usr/share/doc/openvpn*
		rm -f /etc/sysctl.d/20-openvpn.conf
		rm -rf /var/log/openvpn

		# Remove Unbound config
		if [[ -e /etc/unbound/openvpn.conf ]]; then
			removeUnbound
		fi
		echo ""
		echo "OpenVPN removal complete"
	else
		echo ""
		echo "Removal aborted"
	fi
}

function manageMenu () {
	clear
	echo "Welcome to OpenVPN-rapid!"
	echo "A script to rapidly deploy an OpenVPN server on Linux"
	echo "The git repository is available at: https://github.com/benmshapiro/openvpn-rapid"
	echo ""
	echo "It looks like an OpenVPN server is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) Add a new client profile"
	echo "   2) Revoke existing client certificate"
	echo "   3) Remove OpenVPN"
	echo "   4) Exit"
	until [[ "$MENU_OPTION" =~ ^[1-4]$ ]]; do
		read -rp "Select an option [1-4]: " MENU_OPTION
	done

	case $MENU_OPTION in
		1)
			newClient
		;;
		2)
			revokeClient
		;;
		3)
			removeOpenVPN
		;;
		4)
			exit 0
		;;
	esac
}

# Check for root, TUN, OS...
initialCheck

# Check if OpenVPN is already installed
if [[ -e /etc/openvpn/server.conf ]]; then
	manageMenu
else
	installOpenVPN
fi
