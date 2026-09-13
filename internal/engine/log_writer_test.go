package engine

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestLogWriterBoundsUnterminatedLinesAndRecovers(t *testing.T) {
	var output bytes.Buffer
	w := newLogWriter(slog.New(slog.NewTextHandler(&output, nil))).(*logWriter)
	chunk := bytes.Repeat([]byte("a"), 4096)
	for i := 0; i < 1024; i++ {
		if n, err := w.Write(chunk); n != len(chunk) || err != nil {
			t.Fatal("writer failed to drain child")
		}
	}
	if w.buf.Len() > maxEngineLogLine || w.buf.Cap() > 2*maxEngineLogLine {
		t.Fatal("unbounded line buffer")
	}
	w.Write([]byte("\nnext"))
	w.Write([]byte(" line\n"))
	if strings.Count(output.String(), "line truncated") != 1 || !strings.Contains(output.String(), "next line") || w.buf.Len() != 0 {
		t.Fatal("truncation lost the next complete line")
	}
}
