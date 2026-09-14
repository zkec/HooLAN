# MEMORY.md — hoolan project constraints

This file is the permanent record for the HooLAN project. Every session must respect these rules.

- Target Environment: Bare-metal Debian. Do NOT use Docker for the Go backend.
- Core Engines: Sing-box and Xray-core.
- Process Management: The Go app is a systemd service that manages the proxy engines via os/exec.
- Networking Constraints: TPROXY interception using bare-metal nftables at priority -150. The routing rules MUST explicitly bypass local Docker bridge IPs (10.42.42.0/24) and local ports (80, 443, 53) using `fib daddr type local` to prevent breaking the existing NPM, AdGuard, and Jellyfin stack.
