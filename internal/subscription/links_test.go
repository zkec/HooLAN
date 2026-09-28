package subscription

import (
	"reflect"
	"testing"
)

func TestSplitNodeLinks(t *testing.T) {
	a := "vless://test@example.com:443?path=%2Fvless%3A%2F%2F#A name%20"
	b := "trojan://password@example.net:443#B name"
	c := "vmess://encoded-payload"
	for _, separator := range []string{" ", "\t", "\n", "\r\n", "  \t "} {
		got := SplitNodeLinks("  " + a + separator + b + separator + c + "\n")
		if !reflect.DeepEqual(got, []string{a, b, c}) {
			t.Fatalf("separator %q: %#v", separator, got)
		}
	}
	if got := SplitNodeLinks(" \r\n\t "); len(got) != 0 {
		t.Fatalf("empty paste: %#v", got)
	}
	// Unsupported schemes stay separate so validation cannot silently absorb them
	// into the previous configuration's name.
	if got := SplitNodeLinks(a + " snell://unsupported"); len(got) != 2 {
		t.Fatal(got)
	}
}
