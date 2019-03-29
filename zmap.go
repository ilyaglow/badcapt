package badcapt

import (
	"github.com/google/gopacket"
)

const zmapIDHeader = 54321

// ZmapIdentifier adds zmap tag for a packet which
// IP ID header equals 54321.
func ZmapIdentifier(p gopacket.Packet) []string {
	ip4 := unpackIPv4(p)
	if ip4 == nil {
		return nil
	}
	if ip4.Id == zmapIDHeader {
		return []string{"zmap"}
	}

	return nil
}
