package main

import (
	"testing"
)

func TestGuessGateway(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		cidr     int
		expected string
	}{
		{
			name:     "Standard /24 subnet",
			ip:       "192.168.1.100",
			cidr:     24,
			expected: "192.168.1.1",
		},
		{
			name:     "Standard /24 with .1 entered as IP",
			ip:       "192.168.1.1",
			cidr:     24,
			expected: "192.168.1.254",
		},
		{
			name:     "Public WAN /24",
			ip:       "203.0.113.50",
			cidr:     24,
			expected: "203.0.113.1",
		},
		{
			name:     "/30 point-to-point (upper host)",
			ip:       "203.0.113.14",
			cidr:     30,
			expected: "203.0.113.13",
		},
		{
			name:     "/30 point-to-point (lower host)",
			ip:       "203.0.113.13",
			cidr:     30,
			expected: "203.0.113.14",
		},
		{
			name:     "/29 subnet (size 8)",
			ip:       "198.51.100.37",
			cidr:     29,
			expected: "198.51.100.33",
		},
		{
			name:     "/29 subnet with first usable IP",
			ip:       "198.51.100.33",
			cidr:     29,
			expected: "198.51.100.38",
		},
		{
			name:     "/28 subnet (size 16)",
			ip:       "10.20.30.25",
			cidr:     28,
			expected: "10.20.30.17",
		},
		{
			name:     "/31 RFC 3021 subnet (even host)",
			ip:       "10.0.0.2",
			cidr:     31,
			expected: "10.0.0.3",
		},
		{
			name:     "/31 RFC 3021 subnet (odd host)",
			ip:       "10.0.0.3",
			cidr:     31,
			expected: "10.0.0.2",
		},
		{
			name:     "/16 large subnet fills first 3 octets",
			ip:       "172.16.50.100",
			cidr:     16,
			expected: "172.16.50.1",
		},
		{
			name:     "/8 large subnet fills first 3 octets",
			ip:       "10.5.20.88",
			cidr:     8,
			expected: "10.5.20.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := guessGateway(tc.ip, tc.cidr)
			if result != tc.expected {
				t.Errorf("guessGateway(%q, %d) = %q; want %q", tc.ip, tc.cidr, result, tc.expected)
			}
		})
	}
}

func TestCIDRToNetmask(t *testing.T) {
	tests := []struct {
		cidr     int
		expected string
	}{
		{24, "255.255.255.0"},
		{30, "255.255.255.252"},
		{29, "255.255.255.248"},
		{28, "255.255.255.240"},
		{16, "255.255.0.0"},
		{8, "255.0.0.0"},
	}

	for _, tc := range tests {
		res := cidrToNetmask(tc.cidr)
		if res != tc.expected {
			t.Errorf("cidrToNetmask(%d) = %q; want %q", tc.cidr, res, tc.expected)
		}
	}
}
