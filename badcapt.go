package badcapt

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
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

// Marker represents a routine that identifies the raw packet.
type Marker func(gopacket.Packet) []string

var defaultMarkers = []Marker{
	MiraiIdentifier,
	ZmapIdentifier,
	MasscanIdentifier,
	LowMSSIdentifier,
}

// Badcapt defines badcapt configuration
type Badcapt struct {
	client    *elastic.Client
	indexName string
	docType   string
	markers   []Marker
}

// TaggedPacket represents a packet that went through markers.
type TaggedPacket struct {
	Packet gopacket.Packet
	Tags   []string
}

// Record contains packet data, that is ready to be exported
type Record struct {
	SrcIP         net.IP    `json:"src_ip,omitempty"`
	Layers        []string  `json:"layers,omitempty"`
	SrcPort       uint16    `json:"src_port,omitempty"`
	DstIP         net.IP    `json:"dst_ip,omitempty"`
	DstPort       uint16    `json:"dst_port,omitempty"`
	Timestamp     time.Time `json:"date"`
	Tags          []string  `json:"tags"`
	Payload       []byte    `json:"payload,omitempty"`
	PayloadString string    `json:"payload_str,omitempty"`
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
	var layers []string
	for _, l := range tp.Packet.Layers() {
		layers = append(layers, l.LayerType().String())
	}

	var srcIP, dstIP net.IP
	if netLayer := tp.Packet.NetworkLayer(); netLayer != nil {
		srcIP = net.IP(netLayer.NetworkFlow().Src().Raw())
		dstIP = net.IP(netLayer.NetworkFlow().Dst().Raw())
	}

	var srcPort, dstPort uint16
	if trLayer := tp.Packet.TransportLayer(); trLayer != nil {
		srcPort = binary.BigEndian.Uint16(trLayer.TransportFlow().Src().Raw())
		dstPort = binary.BigEndian.Uint16(trLayer.TransportFlow().Dst().Raw())
	}

	var payload []byte
	if appLayer := tp.Packet.ApplicationLayer(); appLayer != nil {
		payload = appLayer.Payload()
	}

	return &Record{
		SrcIP:         srcIP,
		DstIP:         dstIP,
		SrcPort:       srcPort,
		DstPort:       dstPort,
		Timestamp:     tp.Packet.Metadata().CaptureInfo.Timestamp,
		Payload:       payload,
		PayloadString: string(payload),
		Tags:          tp.Tags,
		Layers:        layers,
	}, nil
}

func (b *Badcapt) export(ctx context.Context, tp *TaggedPacket) error {
	record, err := NewRecord(tp)
	if err != nil {
		return err
	}

	if b.client == nil {
		return exportScreen(record)
	}

	return b.exportElastic(ctx, record)
}

func (b *Badcapt) exportElastic(ctx context.Context, record *Record) error {
	_, err := b.client.Index().
		Index(b.indexName).
		Type(b.docType).
		BodyJson(record).
		Do(ctx)

	return err
}

func exportScreen(record *Record) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	fmt.Println(string(data))

	return nil
}

// New bootstraps badcapt configuration.
func New(opts ...func(*Badcapt) error) (*Badcapt, error) {
	conf := &Badcapt{
		client:    nil,
		indexName: indexName,
		docType:   docType,
		markers:   defaultMarkers,
	}

	for _, f := range opts {
		err := f(conf)
		if err != nil {
			return nil, err
		}
	}

	if conf.client == nil {
		return conf, nil
	}

	exists, err := conf.client.IndexExists(indexName).Do(context.Background())
	if err != nil {
		return nil, err
	}

	if !exists {
		_, err := conf.client.CreateIndex(indexName).Do(context.Background())
		if err != nil {
			return nil, err
		}
	}

	return conf, nil
}

// AddPacketMarker adds a packet marking routine.
func AddPacketMarker(m Marker) func(*Badcapt) error {
	return func(b *Badcapt) error {
		b.markers = append(b.markers, m)
		return nil
	}
}

// SetElastic sets elasticsearch client to export events to.
func SetElastic(client *elastic.Client) func(*Badcapt) error {
	return func(b *Badcapt) error {
		b.client = client
		return nil
	}
}

// SetElasticIndexName sets an index name where events are going to be written.
func SetElasticIndexName(name string) func(*Badcapt) error {
	return func(b *Badcapt) error {
		b.indexName = name
		return nil
	}
}

// SetElasticDocType sets the events documents type.
func SetElasticDocType(doc string) func(*Badcapt) error {
	return func(b *Badcapt) error {
		b.docType = doc
		return nil
	}
}

// NewConfig bootstraps badcapt configuration.
// Deprecated. Use New instead.
func NewConfig(elasticLoc string, markers ...Marker) (*Badcapt, error) {
	client, err := elastic.NewClient(
		elastic.SetURL(elasticLoc),
		elastic.SetSniff(false),
	)
	if err != nil {
		return nil, err
	}

	conf := &Badcapt{
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

	if len(markers) == 0 {
		conf.markers = defaultMarkers
	}

	return conf, nil
}

// Listen starts packet sniffing and processing
func (b *Badcapt) Listen(iface string) error {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	err = handle.SetDirection(pcap.DirectionIn)
	if err != nil {
		return nil
	}

	defer handle.Close()
	log.Printf("Started capturing on iface %s", iface)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		p, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println(err)
			continue
		}

		var tags []string

		for _, fn := range b.markers {
			tags = append(tags, fn(p)...)
		}

		if len(tags) == 0 {
			continue
		}

		if err := b.export(context.Background(), &TaggedPacket{p, tags}); err != nil {
			log.Println(err)
		}
	}

	return nil
}
