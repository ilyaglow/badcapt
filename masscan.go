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

	seq := make([]byte, 4)
	binary.BigEndian.PutUint32(seq, tcp.Seq)

	xoredIPSeq := make([]byte, 4)
	fastxor.Bytes(xoredIPSeq, seq, ip4.DstIP)

	dstport := make([]byte, 2)
	binary.BigEndian.PutUint16(dstport, uint16(tcp.DstPort))

	xored := make([]byte, 2)
	fastxor.Bytes(xored, xoredIPSeq, dstport)

	id := make([]byte, 2)
	binary.BigEndian.PutUint16(id, ip4.Id)

	if bytes.Equal(id, xored) {
		return []string{"masscan"}
	}

	return nil
}
