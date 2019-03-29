package badcapt

import (
	"encoding/binary"

	"github.com/google/gopacket"
)

// MiraiIdentifier adds mirai tag for a packet which
// TCP sequence equals destination IP-address
// in a decimal format
func MiraiIdentifier(p gopacket.Packet) []string {
	ip4 := unpackIPv4(p)
	if ip4 == nil {
		return nil
	}

	tcp := unpackTCP(p)
	if tcp == nil {
		return nil
	}

	if binary.BigEndian.Uint32(ip4.DstIP) != tcp.Seq {
		return nil
	}

	return []string{"mirai"}
}
