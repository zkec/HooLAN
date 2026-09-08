module proxy-manager

// No third-party dependencies by design: all netfilter work is done by the
// nftables scripts under scripts/tproxy, and process supervision goes through
// os/exec. Lower this if the Pi's Go package is older than 1.21.
go 1.21
