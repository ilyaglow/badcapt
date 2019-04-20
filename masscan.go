package badcapt

import (
	"encoding/binary"

	"github.com/google/gopacket"
)

// MasscanIdentifier adds masscan tag for a packet which
// IP ID header = dstip ⊕ dstport ⊕ tcpseq.
func MasscanIdentifier(p gopacket.Packet) []string {
	ip4 := unpackIPv4(p)
	if ip4 == nil {
		return nil
	}

	tcp := unpackTCP(p)
	if tcp == nil {
		return nil
	}

	if tcp.SYN == false {
		return nil
	}

	ipUint := binary.BigEndian.Uint32(ip4.DstIP)
	want := ipUint ^ uint32(tcp.DstPort) ^ tcp.Seq

	if uint16(want) == ip4.Id {
		return []string{"masscan"}
	}

	return nil
}
