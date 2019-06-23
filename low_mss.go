package badcapt

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LowMSSIdentifier adds low-mss tag for a packet which TCP Maximum Segment
// Size is less than 500. This fact indicates potential SACK Panic attack
// (CVE-2019-11477).
// Details: https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-001.md#1-cve-2019-11477-sack-panic-linux--2629
func LowMSSIdentifier(p gopacket.Packet) []string {
	tcp := unpackTCP(p)
	if tcp == nil {
		return nil
	}

	if tcp.SYN == false {
		return nil
	}

	for _, o := range tcp.Options {
		if o.OptionType == layers.TCPOptionKindMSS && binary.BigEndian.Uint16(o.OptionData) < 500 {
			return []string{"low-mss"}
		}
	}

	return nil
}
