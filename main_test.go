package main

import (
	"reflect"
	"testing"
)

func TestReorderArgs(t *testing.T) {
	flags := map[string]bool{
		"p":         true,
		"top-ports": true,
		"timeout":   true,
		"proxy":     true,
	}

	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "flags already first — unchanged",
			in:   []string{"-p", "80,443", "scanme.nmap.org"},
			want: []string{"-p", "80,443", "scanme.nmap.org"},
		},
		{
			name: "target before flag — moved to end",
			in:   []string{"scanme.nmap.org", "-p", "80,443"},
			want: []string{"-p", "80,443", "scanme.nmap.org"},
		},
		{
			name: "interleaved — flags pulled forward, targets preserved in order",
			in:   []string{"host1", "-p", "22", "host2", "--silent", "host3"},
			want: []string{"-p", "22", "--silent", "host1", "host2", "host3"},
		},
		{
			name: "long flag with double dash",
			in:   []string{"target", "--top-ports", "100"},
			want: []string{"--top-ports", "100", "target"},
		},
		{
			name: "flag=value form keeps value with flag",
			in:   []string{"target", "-p=80,443"},
			want: []string{"-p=80,443", "target"},
		},
		{
			name: "bool flag does not eat next positional",
			in:   []string{"target", "--silent"},
			want: []string{"--silent", "target"},
		},
		{
			name: "double-dash terminator: everything after is positional",
			in:   []string{"-p", "80", "--", "-weird-host", "host2"},
			want: []string{"-p", "80", "-weird-host", "host2"},
		},
		{
			name: "bare dash is positional (stdin sentinel)",
			in:   []string{"-p", "80", "-"},
			want: []string{"-p", "80", "-"},
		},
		{
			name: "host:port form with later flag",
			in:   []string{"scanme.nmap.org:22", "--proxy", "socks5://h:1080"},
			want: []string{"--proxy", "socks5://h:1080", "scanme.nmap.org:22"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reorderArgs(tt.in, flags)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("reorderArgs(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
