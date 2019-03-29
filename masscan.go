package badcapt

import (
	"bytes"
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/lukechampine/fastxor"
)

// MasscanIdentifier adds zmap tag for a packet which
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

	dstport := make([]byte, 2)
	binary.BigEndian.PutUint16(dstport, uint16(tcp.DstPort))

	seq := make([]byte, 4)
	binary.BigEndian.PutUint32(seq, tcp.Seq)

	xored := make([]byte, 4)
	fastxor.Bytes(xored, seq, ip4.DstIP)
	fastxor.Bytes(xored, xored, dstport)

	id := make([]byte, 2)
	binary.BigEndian.PutUint16(id, ip4.Id)

	if bytes.Equal(id, xored[:2]) {
		return []string{"masscan"}
	}

	return nil
}
