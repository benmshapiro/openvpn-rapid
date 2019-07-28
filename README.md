# openvpn-rapid
A script to rapidly deploy an OpenVPN server on Linux.

## Features
- Installs and configures an operative OpenVPN server.
- OpenVPN 2.4 features: including customizable encryption settings and enhanced default settings.
- Choice of self-hosted or popular public DNS resolvers (pushed to clients).
- Manage client certificates; Add and Revoke certs using this script.
- Script option to cleanly remove OpenVPN from Host (even configuration files and iptable rules).

## Dependencies
Supports current releases for Debian, Fedora, CentOS, Ubuntu, and Arch Linux.

## Installation
Clone the repository and make the install script executable:
```
curl -O https://raw.githubusercontent.com/benmshapiro/openvpn-rapid/master/openvpn-rapid.sh
chmod +x openvpn-rapid.sh
```
Then run the install script:
```
./openvpn-rapid.sh
```
NOTE: Run the script as root and have the TUN module enabled.

## Usage
The first time you run this script, you'll have to answer a few questions to setup your OpenVPN server.

When OpenVPN is installed, you can run the script again, and you will get the choice to :

- Add a client
- Remove a client
- Uninstall OpenVPN

.OVPN are placed in your home directory after adding a new client. Download them from your server and connect using your favorite OpenVPN client.

## Options
This script provides stronger default security and encryption settings for OpenVPN than it's stock configuration.

### Compression
Compression is disabled, but the script provides options for LZ0 and LZ4 (v1/v2) algorithms.

### TLS version
TLS version 1.2 is enforced.

### Certificate
Elliptic curve cryptography (ECDSA) with prime256v1 curve is default. OpenVPN 2.4 added support for ECDSA that is faster, lighter and more secure. The script provides the us of RSA certs if needed.

### Data Channel
The default cipher is set to AES-128-GCM. AES is today's standard, the fastest and more secure cipher available today. The script uses the 128 bits key with AES because using a larger key is much slower (AES-256 is 40% slower) [CITATION NEEDED]. Larger keys are also vulnerable to timing attacks [CITATION NEEDED]. The option of using AES in Cipher Block Chaining (AES-CBC) is also provided:

-AES-128-GCM
-AES-192-GCM
-AES-256-GCM
-AES-128-CBC
-AES-192-CBC
-AES-256-CBC

### Control-Channel
The script provides the following options for negotiation, depending on the certificate used:
-ECDSA:
--TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256 - Default
--TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
-RSA:
-TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
--TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384

### Diffie-Hellman (DH) key exchange
Generating DH keys can take a long time. ECDH keys are generated quick and ephemeral (generated on demand). So, ECDH key with prime256v1 curve is default for fast, more secure implementation. The script provides options for both ECDH and DH keys:

ECDH: prime256v1,secp384r1, and secp521r1 curves
DH: 2048,3072, and 4096 bits keys

### HMAC digest algorithm
HMAC is a commonly used message authentication algorithm (MAC) that uses a data string, a secure hash algorithm, and a key, to produce a digital signature. The following options are available:

- SHA256 - default
- SHA384
- SHA512

### tls-auth and tls-crypt
The script uses tls-crypt by default.'tls-auth' and 'tls-crypt' provide an additional layer of security and mitigate DoS attacks. They aren't used by default by OpenVPN.

## Contribute

Found an issue? Post it in the [issue tracker](https://github.com/benmshapiro/openvpn-rapid/issues). <br> 
Want to add another awesome feature? [Fork](https://github.com/benmshapiro/openvpn-rapid/fork) this repository and add your feature, then send a pull request.

## License
The MIT License (MIT)
Copyright &copy; 2019 Ben Shapiro