package subscription

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ShareLink serializes current settings; never silently exports a chain as one hop.
func ShareLink(n Node) (string, error) {
	if n.ChainInternal || n.Detour != "" {
		return "", fmt.Errorf("a multi-hop chain cannot be represented by one mobile share link")
	}
	if err := n.Validate(); err != nil {
		return "", err
	}
	if n.Protocol == ProtoVMess {
		if n.Security == SecReality {
			return "", fmt.Errorf("VMess Reality share links are unsupported")
		}
		path := n.Path
		if n.Transport == TransportGRPC {
			path = n.ServiceName
		}
		data := map[string]any{"v": "2", "ps": n.Tag, "add": n.Server, "port": strconv.Itoa(n.Port), "id": n.UUID, "aid": strconv.Itoa(n.AlterID), "scy": n.Method, "net": string(n.Transport), "type": "none", "host": n.Host, "path": path, "tls": string(n.Security), "sni": n.SNI, "alpn": strings.Join(n.ALPN, ","), "fp": n.Fingerprint, "allowInsecure": n.Insecure}
		raw, err := json.Marshal(data)
		if err != nil {
			return "", err
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(raw), nil
	}
	if n.Protocol == ProtoShadowsocks {
		if n.Security != SecNone || n.Transport != "" && n.Transport != TransportTCP {
			return "", fmt.Errorf("Shadowsocks share format cannot preserve these transport settings")
		}
		return "ss://" + base64.RawURLEncoding.EncodeToString([]byte(n.Method+":"+n.Password)) + "@" + net.JoinHostPort(n.Server, strconv.Itoa(n.Port)) + "#" + url.QueryEscape(n.Tag), nil
	}
	if n.Protocol != ProtoVLESS && n.Protocol != ProtoTrojan && n.Protocol != ProtoHysteria2 {
		return "", fmt.Errorf("unsupported sharing protocol")
	}
	credential := n.Password
	if n.Protocol == ProtoVLESS {
		credential = n.UUID
	}
	u := url.URL{Scheme: string(n.Protocol), Host: net.JoinHostPort(n.Server, strconv.Itoa(n.Port)), User: url.User(credential), Fragment: n.Tag}
	q := url.Values{}
	for key, value := range map[string]string{"security": string(n.Security), "type": string(n.Transport), "sni": n.SNI, "alpn": strings.Join(n.ALPN, ","), "fp": n.Fingerprint, "pbk": n.PublicKey, "sid": n.ShortID, "flow": n.Flow, "path": n.Path, "host": n.Host, "serviceName": n.ServiceName} {
		if value != "" {
			q.Set(key, value)
		}
	}
	if n.Insecure {
		q.Set("allowInsecure", "1")
	}
	u.RawQuery = q.Encode()
	// net/url escapes the fragment once, preserving literal plus and percent signs.
	return u.String(), nil
}
