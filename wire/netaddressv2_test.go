package wire

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// TestIsIPv4Mapped tests that isIPv4Mapped correctly identifies IPv4-mapped
// IPv6 addresses.
func TestIsIPv4Mapped(t *testing.T) {
	tests := []struct {
		name     string
		addr     []byte
		expected bool
	}{
		{
			name: "IPv4-mapped ::ffff:192.0.2.1",
			addr: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0xff, 0xff, 0xc0, 0x00, 0x02, 0x01,
			},
			expected: true,
		},
		{
			name: "IPv4-mapped ::ffff:127.0.0.1",
			addr: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01,
			},
			expected: true,
		},
		{
			name: "Regular IPv6",
			addr: []byte{
				0x20, 0x01, 0x09, 0xe8, 0x26, 0x15, 0x73, 0x00,
				0x09, 0x54, 0x12, 0x63, 0xef, 0xc8, 0x2e, 0x34,
			},
			expected: false,
		},
		{
			name: "OnionCat Tor address",
			addr: []byte{
				0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43, 0xff, 0xfe,
				0xcc, 0x39, 0xa8, 0x73, 0x69, 0x15, 0xff, 0xff,
			},
			expected: false,
		},
		{
			name:     "Short address (IPv4)",
			addr:     []byte{0x7f, 0x00, 0x00, 0x01},
			expected: false,
		},
		{
			name:     "Empty address",
			addr:     []byte{},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := isIPv4Mapped(test.addr)
			if result != test.expected {
				t.Errorf("isIPv4Mapped(%v) = %v, want %v",
					test.addr, result, test.expected)
			}
		})
	}
}

// TestNetAddressV2FromBytes tests that NetAddressV2FromBytes works as
// expected.
func TestNetAddressV2FromBytes(t *testing.T) {
	tests := []struct {
		addrBytes       []byte
		expectedString  string
		expectedNetwork string
	}{
		// Ipv4 encoding
		{
			[]byte{0x7f, 0x00, 0x00, 0x01},
			"127.0.0.1",
			string(ipv4),
		},

		// Ipv6 encoding
		{
			[]byte{
				0x20, 0x01, 0x09, 0xe8, 0x26, 0x15, 0x73, 0x00,
				0x09, 0x54, 0x12, 0x63, 0xef, 0xc8, 0x2e, 0x34,
			},
			"2001:9e8:2615:7300:954:1263:efc8:2e34",
			string(ipv6),
		},

		// IPv4-mapped IPv6 encoding (::ffff:127.0.0.1) should be
		// converted to IPv4.
		{
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01,
			},
			"127.0.0.1",
			string(ipv4),
		},

		// OnionCat encoding
		{
			[]byte{
				0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43, 0xff, 0xfe,
				0xcc, 0x39, 0xa8, 0x73, 0x69, 0x15, 0xff, 0xff,
			},
			"777myonionurl777.onion",
			string(torv2),
		},

		// Torv2 encoding
		{
			[]byte{
				0xff, 0xfe, 0xcc, 0x39, 0xa8, 0x73, 0x69, 0x15,
				0xff, 0xff,
			},
			"777myonionurl777.onion",
			string(torv2),
		},

		// Torv3 encoding
		{
			[]byte{
				0xca, 0xd2, 0xd3, 0xc8, 0xdc, 0x9c, 0xc4, 0xd3,
				0x70, 0x33, 0x30, 0xc5, 0x23, 0xaf, 0x02, 0xed,
				0xc4, 0x9d, 0xf8, 0xc6, 0xb0, 0x4e, 0x74, 0x6d,
				0x3b, 0x51, 0x57, 0xa7, 0x15, 0xfe, 0x98, 0x35,
			},
			"zljnhsg4ttcng4btgdcshlyc5xcj36ggwbhhi3j3kfl2ofp6ta26jlid.onion",
			string(torv3),
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		na := NetAddressV2FromBytes(time.Time{}, 0, test.addrBytes, 0)

		if test.expectedNetwork != string(torv3) {
			if na.ToLegacy() == nil {
				t.Errorf("Test #%d has nil legacy encoding", i)
			}
		} else {
			if !na.IsTorV3() {
				t.Errorf("Test #%d is not torv3 address", i)
			}
		}

		if na.Addr.String() != test.expectedString {
			t.Errorf("Test #%d did not match expected string", i)
		}

		if na.Addr.Network() != test.expectedNetwork {
			t.Errorf("Test #%d did not match expected network", i)
		}

		var b bytes.Buffer
		if err := writeNetAddressV2(&b, 0, na); err != nil {
			t.Errorf("Test #%d failed writing address %v", i, err)
		}

		// Assert that the written netID is equivalent to the above.
		if string(b.Bytes()[5]) != test.expectedNetwork {
			t.Errorf("Test #%d did not match expected network", i)
		}
	}
}

// TestReadNetAddressV2 tests that readNetAddressV2 behaves as expected in
// different scenarios.
func TestReadNetAddressV2(t *testing.T) {
	tests := []struct {
		buf             []byte
		expectedNetwork string
		expectedError   error
	}{
		// Invalid address size for unknown netID.
		{
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfd, 0xff,
				0xff,
			},
			"",
			ErrInvalidAddressSize,
		},

		// Valid address size for unknown netID.
		{
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x20, 0x10,
				0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
				0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
				0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
				0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x22,
				0x22,
			},
			"",
			ErrSkippedNetworkID,
		},

		// Invalid ipv4 size.
		{
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x05},
			"",
			ErrInvalidAddressSize,
		},

		// Valid ipv4 encoding.
		{
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x7f,
				0x00, 0x00, 0x01, 0x22, 0x22,
			},
			string(ipv4),
			nil,
		},

		// Invalid ipv6 size.
		{
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xfc},
			"",
			ErrInvalidAddressSize,
		},

		// OnionCat encoding is skipped.
		{
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x10, 0xfd,
				0x87, 0xd8, 0x7e, 0xeb, 0x43, 0xff, 0xfe, 0xcc,
				0x39, 0xa8, 0x73, 0x69, 0x15, 0xff, 0xff, 0x22,
				0x22,
			},
			"",
			ErrSkippedNetworkID,
		},

		// IPv4-mapped IPv6 encoding is skipped (::ffff:192.0.2.1).
		{
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x10, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0xff, 0xff, 0xc0, 0x00, 0x02, 0x01, 0x22,
				0x22,
			},
			"",
			ErrSkippedNetworkID,
		},

		// Valid ipv6 encoding.
		{
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x10, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x22,
				0x22,
			},
			string(ipv6),
			nil,
		},

		// Invalid torv2 size.
		{
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x02},
			"",
			ErrInvalidAddressSize,
		},

		// Valid torv2 encoding.
		{
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x0a, 0x20,
				0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
				0x20, 0x22, 0x22,
			},
			string(torv2),
			nil,
		},

		// Invalid torv3 size.
		{
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02},
			"",
			ErrInvalidAddressSize,
		},

		// Valid torv3 encoding.
		{
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x20, 0x10,
				0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
				0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
				0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
				0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x22,
				0x22,
			},
			string(torv3),
			nil,
		},

		// Invalid i2p size.
		{
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x02},
			"",
			ErrInvalidAddressSize,
		},

		// Valid i2p encoding.
		{
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x10,
				0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
				0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
				0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
				0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x22,
				0x22,
			},
			string(i2p),
			nil,
		},

		// Invalid cjdns size.
		{
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x02},
			"",
			ErrInvalidAddressSize,
		},

		// Valid cjdns encoding.
		{
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x10, 0x20,
				0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
				0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22,
				0x22,
			},
			string(cjdns),
			nil,
		},

		// Invalid yggdrasil size.
		{
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x02},
			"",
			ErrInvalidAddressSize,
		},

		// Valid yggdrasil encoding.
		{
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x10, 0x02,
				0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
				0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22,
				0x22,
			},
			string(yggdrasil),
			nil,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		r := bytes.NewReader(test.buf)
		na := &NetAddressV2{}

		err := readNetAddressV2(r, 0, na)
		if err != test.expectedError {
			t.Errorf("Test #%d had unexpected error %v", i, err)
		} else if err != nil {
			continue
		}

		// Trying to read more should give EOF.
		var b [1]byte
		if _, err := r.Read(b[:]); err != io.EOF {
			t.Errorf("Test #%d did not cleanly finish reading", i)
		}

		if na.Addr.Network() != test.expectedNetwork {
			t.Errorf("Test #%d had unexpected network %v", i,
				na.Addr.Network())
		}
	}
}

// TestNetAddressV2Overlay tests that i2p, cjdns, and yggdrasil addresses
// survive an encode and decode round trip, report their type, and print in
// their usual text form.
func TestNetAddressV2Overlay(t *testing.T) {
	var i2pKey [i2pSize]byte
	for i := range i2pKey {
		i2pKey[i] = byte(i)
	}

	tests := []struct {
		name        string
		addr        net.Addr
		isI2P       bool
		isCJDNS     bool
		isYggdrasil bool
		str         string
	}{
		{
			name:  "i2p",
			addr:  &i2pAddr{addr: i2pKey, netID: i2p},
			isI2P: true,
			str:   "aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq.b32.i2p",
		},
		{
			name: "cjdns",
			addr: &cjdnsAddr{
				addr:  [cjdnsSize]byte{0xfc, 15: 0x01},
				netID: cjdns,
			},
			isCJDNS: true,
			str:     "fc00::1",
		},
		{
			name: "yggdrasil",
			addr: &yggdrasilAddr{
				addr:  [yggdrasilSize]byte{0x02, 15: 0x01},
				netID: yggdrasil,
			},
			isYggdrasil: true,
			str:         "200::1",
		},
	}

	for _, test := range tests {
		na := &NetAddressV2{
			Timestamp: time.Unix(0x495fab29, 0),
			Services:  SFNodeNetwork,
			Addr:      test.addr,
			Port:      8333,
		}

		var buf bytes.Buffer
		if err := writeNetAddressV2(&buf, 0, na); err != nil {
			t.Fatalf("%s: write failed: %v", test.name, err)
		}

		decoded := &NetAddressV2{}
		if err := readNetAddressV2(&buf, 0, decoded); err != nil {
			t.Fatalf("%s: read failed: %v", test.name, err)
		}

		if decoded.IsI2P() != test.isI2P ||
			decoded.IsCJDNS() != test.isCJDNS ||
			decoded.IsYggdrasil() != test.isYggdrasil {

			t.Errorf("%s: unexpected address type %T", test.name,
				decoded.Addr)
		}

		if decoded.Addr.String() != test.str {
			t.Errorf("%s: got address %q, want %q", test.name,
				decoded.Addr.String(), test.str)
		}

		if decoded.Port != na.Port {
			t.Errorf("%s: got port %d, want %d", test.name,
				decoded.Port, na.Port)
		}
	}
}
