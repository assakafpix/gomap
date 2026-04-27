package ports

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		wantLen int
		want    []int // if non-nil, must equal exactly
		wantErr bool
	}{
		{name: "single", spec: "80", want: []int{80}},
		{name: "list", spec: "22,80,443", want: []int{22, 80, 443}},
		{name: "range", spec: "1-5", want: []int{1, 2, 3, 4, 5}},
		{name: "mixed", spec: "22,80-82,443", want: []int{22, 80, 81, 82, 443}},
		{name: "all", spec: "-", wantLen: 65535},
		{name: "tcp prefix", spec: "T:80,T:443", want: []int{80, 443}},
		{name: "udp dropped", spec: "T:80,U:53", want: []int{80}},
		{name: "dedup", spec: "80,80,80", want: []int{80}},
		{name: "open-ended start", spec: "-1024", wantLen: 1024},
		{name: "open-ended end", spec: "65530-", wantLen: 6},
		{name: "whitespace", spec: " 22 , 80 ", want: []int{22, 80}},

		{name: "empty", spec: "", wantErr: true},
		{name: "out of range", spec: "70000", wantErr: true},
		{name: "zero", spec: "0", wantErr: true},
		{name: "garbage", spec: "abc", wantErr: true},
		{name: "reverse range", spec: "100-50", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse(%q) err=%v, wantErr=%v", tt.spec, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.want != nil {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("Parse(%q)=%v, want %v", tt.spec, got, tt.want)
				}
			}
			if tt.wantLen > 0 && len(got) != tt.wantLen {
				t.Errorf("Parse(%q) len=%d, want %d", tt.spec, len(got), tt.wantLen)
			}
		})
	}
}

func TestTopN(t *testing.T) {
	tests := []struct {
		n       int
		wantLen int
		first   int // expected first port
	}{
		{n: 10, wantLen: 10, first: 80},
		{n: 100, wantLen: 100, first: 80},
		{n: 1000, wantLen: 1000, first: 80},
		{n: 5, wantLen: 5, first: 80},
		{n: 50, wantLen: 50, first: 80},
		{n: 5000, wantLen: 1000, first: 80}, // clamped
		{n: 0, wantLen: 0},
	}
	for _, tt := range tests {
		got := TopN(tt.n)
		if len(got) != tt.wantLen {
			t.Errorf("TopN(%d) len=%d, want %d", tt.n, len(got), tt.wantLen)
		}
		if tt.wantLen > 0 && got[0] != tt.first {
			t.Errorf("TopN(%d)[0]=%d, want %d", tt.n, got[0], tt.first)
		}
	}
}

func TestTopNTopValues(t *testing.T) {
	// Verify the well-known top ports are in the right order.
	want := []int{80, 23, 443, 21, 22, 25, 3389, 110, 445, 139}
	got := TopN(10)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TopN(10)=%v, want %v", got, want)
	}
}

func TestServiceName(t *testing.T) {
	tests := []struct {
		port int
		want string
	}{
		{22, "ssh"},
		{80, "http"},
		{443, "https"},
		{3306, "mysql"},
		{5432, "postgresql"},
		{6379, "redis"},
		{27017, "mongod"},
		{53, "domain"},
		{389, "ldap"},
		{4, ""}, // unallocated
	}
	for _, tt := range tests {
		got := ServiceName(tt.port)
		if got != tt.want {
			t.Errorf("ServiceName(%d)=%q, want %q", tt.port, got, tt.want)
		}
	}
}
