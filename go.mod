module hoolan

// No third-party dependencies by design: all netfilter work is done by the
// nftables scripts under scripts/tproxy, and process supervision goes through
// os/exec. Build with a maintained toolchain supporting Go 1.21 or later.
go 1.21
