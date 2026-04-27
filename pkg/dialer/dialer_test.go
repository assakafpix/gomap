package dialer

import (
	"testing"
	"time"
)

func TestNew_Direct(t *testing.T) {
	d, err := New("", 5*time.Second)
	if err != nil {
		t.Fatalf("direct dialer: %v", err)
	}
	if d == nil {
		t.Fatal("expected non-nil dialer")
	}
}

func TestMaskCredentials(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"socks5://user:pass@localhost:1080", "socks5://****@localhost:1080"},
		{"socks5://localhost:1080", "socks5://localhost:1080"},
		{"user:pass@localhost:1080", "****@localhost:1080"},
	}
	for _, tt := range tests {
		got := MaskCredentials(tt.input)
		if got != tt.want {
			t.Errorf("MaskCredentials(%q)=%q, want=%q", tt.input, got, tt.want)
		}
	}
}
