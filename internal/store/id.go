package store

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"proxy-manager/internal/subscription"
)

// NodeID derives a stable identity for a node from the fields that define
// *which server you are talking to*, deliberately excluding the display tag.
//
// Providers rename nodes constantly -- "US-1" becomes "🇺🇸 US-1 | 2x" between two
// refreshes of the same subscription. Keying on the tag would orphan every
// latency measurement on each rename and grow the store without bound. Keying
// on server+port+credential means a rename is an update, not a new row.
//
// Excluded on purpose:
//   - Tag: display-only, provider-controlled, changes freely.
//   - Detour: local operator intent; chaining a node must not re-identify it.
//   - Insecure/Fingerprint/ALPN: tuning knobs that do not change the endpoint.
//
// Included: protocol, server, port, and the credential, because a rotated
// credential genuinely is a different access grant and its history should not
// carry over. Transport and SNI/path are included since a provider offering
// both ws and grpc on one host:port are two distinct endpoints.
func NodeID(n subscription.Node) string {
	// Length-prefixed join: without it, ("ab","c") and ("a","bc") would hash
	// identically and two different servers could collide onto one record.
	var b strings.Builder
	write := func(s string) {
		b.WriteString(strconv.Itoa(len(s)))
		b.WriteByte(':')
		b.WriteString(s)
		b.WriteByte('|')
	}
	write(string(n.Protocol))
	write(strings.ToLower(n.Server))
	write(strconv.Itoa(n.Port))
	write(credentialOf(n))
	write(string(n.Transport))
	write(string(n.Security))
	write(n.SNI)
	write(n.Path)
	write(n.ServiceName)

	sum := sha256.Sum256([]byte(b.String()))
	// 128 bits is ample for hundreds of rows and keeps the file readable.
	return hex.EncodeToString(sum[:16])
}

// credentialOf returns the protocol's identifying secret.
func credentialOf(n subscription.Node) string {
	switch n.Protocol {
	case subscription.ProtoVLESS, subscription.ProtoVMess:
		return n.UUID
	case subscription.ProtoShadowsocks:
		return n.Method + ":" + n.Password
	default:
		return n.Password
	}
}

// KeepSet builds the argument for Prune from a parsed subscription.
func KeepSet(nodes []subscription.Node) map[string]bool {
	keep := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		keep[NodeID(n)] = true
	}
	return keep
}
