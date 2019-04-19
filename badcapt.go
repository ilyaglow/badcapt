package badcapt

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/olivere/elastic"
)

const (
	indexName = "badcapt"
	docType   = "bcrecord"
)

var defaultChecks = []func(gopacket.Packet) []string{
	MiraiIdentifier,
	ZmapIdentifier,
	MasscanIdentifier,
}

// Config defines badcapt configuration
type Config struct {
	client    *elastic.Client
	indexName string
	docType   string
	checks    []func(gopacket.Packet) []string
}

// TaggedPacket represents a packet that went through checks
type TaggedPacket struct {
	Packet gopacket.Packet
	Tags   []string
}

// Record contains packet data, that is ready to be exported
type Record struct {
	SrcIP          net.IP    `json:"src_ip,omitempty"`
	TransportProto string    `json:"transport"`
	SrcPort        uint16    `json:"src_port"`
	DstIP          net.IP    `json:"dst_ip,omitempty"`
	DstPort        uint16    `json:"dst_port"`
	Timestamp      time.Time `json:"date"`
	Tags           []string  `json:"tags"`
	Payload        []byte    `json:"payload,omitempty"`
	PayloadString  string    `json:"payload_str,omitempty"`
}

func unpackIPv4(p gopacket.Packet) *layers.IPv4 {
	ip4Layer := p.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return nil
	}
	ip4 := ip4Layer.(*layers.IPv4)

	return ip4
}

func unpackTCP(p gopacket.Packet) *layers.TCP {
	tcpLayer := p.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}
	tcp := tcpLayer.(*layers.TCP)

	return tcp
}

// NewRecord constructs a record to write to the database
func NewRecord(tp *TaggedPacket) (*Record, error) {
	ip4 := unpackIPv4(tp.Packet)
	if ip4 == nil {
		return nil, errors.New("not ip4 type packet")
	}

	udpLayer := tp.Packet.Layer(layers.LayerTypeUDP)
	tcpLayer := tp.Packet.Layer(layers.LayerTypeTCP)
	var (
		srcPort   uint16
		dstPort   uint16
		transport string
	)

	if tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		transport = "tcp"
	} else if udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		transport = "udp"
	} else {
		return nil, errors.New("nor tcp nor udp type packet")
	}

	var payload []byte
	appLayer := tp.Packet.ApplicationLayer()
	if appLayer != nil {
		payload = appLayer.Payload()
	}

	return &Record{
		SrcIP:          ip4.SrcIP,
		DstIP:          ip4.DstIP,
		SrcPort:        srcPort,
		DstPort:        dstPort,
		Timestamp:      tp.Packet.Metadata().CaptureInfo.Timestamp,
		Payload:        payload,
		PayloadString:  string(payload),
		Tags:           tp.Tags,
		TransportProto: transport,
	}, nil
}

func (c *Config) export(ctx context.Context, tp *TaggedPacket) error {
	record, err := NewRecord(tp)
	if err != nil {
		return err
	}

	if c.client == nil {
		return c.exportScreen(record)
	}

	return c.exportElastic(ctx, record)
}

func (c *Config) exportElastic(ctx context.Context, record *Record) error {
	_, err := c.client.Index().
		Index(c.indexName).
		Type(c.docType).
		BodyJson(record).
		Do(ctx)

	return err
}

func (c *Config) exportScreen(record *Record) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	log.Println(string(data))

	return nil
}

// New bootstraps badcapt configuration.
func New(opts ...func(*Config) error) (*Config, error) {
	conf := &Config{
		client:    nil,
		indexName: indexName,
		docType:   docType,
		checks:    defaultChecks,
	}

	for _, f := range opts {
		err := f(conf)
		if err != nil {
			return nil, err
		}
	}

	return conf, nil
}

// NewConfig bootstraps badcapt configuration
func NewConfig(elasticLoc string, checks ...func(gopacket.Packet) []string) (*Config, error) {
	client, err := elastic.NewClient(
		elastic.SetURL(elasticLoc),
		elastic.SetSniff(false),
	)
	if err != nil {
		return nil, err
	}

	conf := &Config{
		client:    client,
		indexName: indexName,
		docType:   docType,
	}

	exists, err := client.IndexExists(indexName).Do(context.Background())
	if err != nil {
		return nil, err
	}

	if !exists {
		_, err := client.CreateIndex(indexName).Do(context.Background())
		if err != nil {
			return nil, err
		}
	}

	if len(checks) == 0 {
		conf.checks = defaultChecks
	}

	return conf, nil
}

// Listen starts packet sniffing and processing
func (c *Config) Listen(iface string) error {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()
	log.Printf("Started capturing on iface %s", iface)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for p := range packetSource.Packets() {
		var tags []string

		for _, fn := range c.checks {
			tags = append(tags, fn(p)...)
		}

		if len(tags) == 0 {
			continue
		}

		if err := c.export(context.Background(), &TaggedPacket{p, tags}); err != nil {
			log.Println(err)
		}
	}

	return nil
}
