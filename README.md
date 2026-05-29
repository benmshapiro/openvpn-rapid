# openvpn-rapid

A script to rapidly deploy a modern OpenVPN server on Linux with secure defaults and simple client management.

## Quick Start

```bash
curl -O https://raw.githubusercontent.com/benmshapiro/openvpn-rapid/master/openvpn-rapid.sh
sudo bash openvpn-rapid.sh
```

Follow the prompts and import the generated `.ovpn` profile into your OpenVPN client.

## Features

- Installs and configures a fully functional OpenVPN server
- Modern OpenVPN configuration with secure defaults
- Supports ECDSA and RSA certificates
- Choice of self-hosted or public DNS resolvers
- Create and revoke client certificates
- Automatic firewall and IP forwarding configuration
- Clean OpenVPN removal option
- Generates ready-to-use `.ovpn` client profiles

## Supported Operating Systems

- Debian
- Ubuntu
- Fedora
- CentOS
- RHEL
- Rocky Linux
- AlmaLinux
- Arch Linux
- Manjaro

## Requirements

- Root access
- systemd
- `/dev/net/tun`

## What This Script Configures

The installer automatically:

- Installs OpenVPN and required dependencies
- Creates a public key infrastructure (PKI)
- Generates server and client certificates
- Enables IPv4 forwarding
- Configures NAT and forwarding firewall rules
- Creates a systemd service to restore firewall rules after reboot
- Generates OpenVPN client profiles

## Initial Configuration

When run for the first time, the script prompts for:

- VPN listen IPv4 address
- Public endpoint (if behind NAT)
- OpenVPN port
- Protocol (UDP or TCP)
- DNS provider
- Certificate type
- Initial client name
- Client key protection option

### DNS Provider Options

1. Current system resolvers
2. Self-hosted Unbound
3. Cloudflare
4. Quad9
5. OpenDNS
6. Google

### Certificate Options

- ECDSA (`prime256v1`)
- RSA 3072-bit

### Client Key Options

- Passwordless
- Password-protected

## Security Defaults

The script favors secure modern defaults:

- TLS minimum version: 1.2
- `tls-crypt`
- `auth SHA256`
- ECDH curve: `prime256v1`
- `dh none`
- Certificate revocation list (CRL) support
- Redirect all client traffic through the VPN

### Data Channel Ciphers

```text
AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
```

Fallback cipher:

```text
AES-256-GCM
```

## OpenVPN Compatibility

The generated configuration is intended for OpenVPN 2.5+ and OpenVPN Connect clients.

Older OpenVPN clients may not support the configured cipher suite or TLS settings.

## Usage

After installation, running the script again displays:

1. Add a new client profile
2. Revoke an existing client certificate
3. Remove OpenVPN
4. Exit

### Adding Additional Clients

Run:

```bash
sudo bash openvpn-rapid.sh
```

Then select **Add a new client profile**.

### Revoking Clients

Revoking a client certificate prevents that certificate from authenticating to the VPN.

Deleting an `.ovpn` file alone does not revoke access.

### Client Profile Location

Generated client profiles are saved to:

- `/home/$SUDO_USER/<client>.ovpn` when run with sudo
- `/root/<client>.ovpn` when run directly as root

## Firewall Configuration

The script automatically:

- Enables IPv4 forwarding
- Creates NAT and forwarding rules
- Creates:

```text
/etc/iptables/add-openvpn-rules.sh
/etc/iptables/rm-openvpn-rules.sh
```

- Installs and enables:

```text
iptables-openvpn.service
```

## Cloud Provider Notes

If hosted behind a cloud firewall or security group, ensure the selected OpenVPN port is allowed.

Examples:

- AWS Security Groups
- Google Cloud Firewall Rules
- Azure Network Security Groups
- Oracle Cloud Security Lists

## Troubleshooting

### Cannot Connect

Verify:

- OpenVPN is running
- The selected port is open
- Cloud firewall rules allow traffic
- The `.ovpn` profile contains the correct public IP or hostname

### TUN Device Missing

Verify `/dev/net/tun` exists and is enabled by your provider.

### DNS Not Resolving

Reconnect the VPN client and verify the selected DNS provider is reachable.

## Useful Commands

Check OpenVPN status:

```bash
systemctl status openvpn-server@server
```

Check firewall service:

```bash
systemctl status iptables-openvpn
```

View logs:

```bash
journalctl -u openvpn-server@server
```

Check listening ports:

```bash
ss -tulpn | grep openvpn
```

## Uninstalling OpenVPN

Selecting **Remove OpenVPN** will:

- Stop and disable OpenVPN services
- Stop and disable `iptables-openvpn.service`
- Remove OpenVPN packages
- Remove generated client profiles
- Remove firewall helper scripts
- Remove OpenVPN configuration files
- Remove Easy-RSA data and certificates
- Remove log files
- Remove IP forwarding configuration

Including cleanup of:

```text
/etc/openvpn
/var/log/openvpn
/etc/sysctl.d/20-openvpn.conf
```

## Security Philosophy

This project favors:

- Secure defaults
- Minimal user decisions
- Strong cryptography
- Modern TLS configuration
- Easy maintenance

## Contributing

Issues and pull requests are welcome.

Repository:

https://github.com/benmshapiro/openvpn-rapid

## License

MIT License

Copyright © 2019–2026 Ben Shapiro
