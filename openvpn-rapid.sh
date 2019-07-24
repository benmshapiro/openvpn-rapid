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