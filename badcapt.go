package badcapt

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
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
	elasticClient    *elastic.Client
	indexName        string
	docType          string
	markers          []Marker
	exportFunc       func(context.Context, *Record) error
	portsDescription NmapServices
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
	DstService    string    `json:"dst_service,omitempty"`
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

// NewRecord constructs a record for export.
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

	if b.portsDescription != nil {
		var proto string
		for _, p := range record.Layers {
			if p == "TCP" || p == "UDP" || p == "SCTP" {
				proto = strings.ToLower(p)
				break
			}
		}
		if proto != "" {
			record.DstService = b.portsDescription[fmt.Sprintf("%d/%s", record.DstPort, proto)]
		}
	}

	return b.exportFunc(ctx, record)
}

func (b *Badcapt) exportElastic(ctx context.Context, record *Record) error {
	_, err := b.elasticClient.Index().
		Index(b.indexName).
		Type(b.docType).
		BodyJson(record).
		Do(ctx)

	return err
}

func (b *Badcapt) exportScreen(_ context.Context, record *Record) error {
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
		elasticClient: nil,
		indexName:     indexName,
		docType:       docType,
		markers:       defaultMarkers,
	}
	conf.exportFunc = conf.exportScreen

	for _, f := range opts {
		err := f(conf)
		if err != nil {
			return nil, err
		}
	}

	if conf.elasticClient == nil {
		return conf, nil
	}

	exists, err := conf.elasticClient.IndexExists(indexName).Do(context.Background())
	if err != nil {
		return nil, err
	}

	if !exists {
		_, err := conf.elasticClient.CreateIndex(indexName).Do(context.Background())
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
		b.elasticClient = client
		b.exportFunc = b.exportElastic
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

// SetExportFunc to export events the way user want.
func SetExportFunc(fn func(ctx context.Context, rec *Record) error) func(*Badcapt) error {
	return func(b *Badcapt) error {
		b.exportFunc = fn
		return nil
	}
}

// SetNmapServicesPath to translate port number to a service name.
func SetNmapServicesPath(path string) func(*Badcapt) error {
	var err error
	return func(b *Badcapt) error {
		b.portsDescription, err = ParseNmapServices(path)
		if err != nil {
			return fmt.Errorf("parsing nmap-services file: %w", err)
		}
		log.Printf("parsed descriptions for %d ports", len(b.portsDescription))
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
		elasticClient: client,
		indexName:     indexName,
		docType:       docType,
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
