package badcapt

import (
	"encoding/csv"
	"io"
	"os"
)

// DefaultNmapServicesPath is used to translate port number to service name.
var DefaultNmapServicesPath = "/usr/share/nmap/nmap-services"

// NmapServices is map of "port/protocol" and service name.
type NmapServices map[string]string

// ParseNmapServices file to a map.
func ParseNmapServices(path string) (NmapServices, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	r := csv.NewReader(f)
	r.Comma = '\t'
	r.Comment = '#'
	r.FieldsPerRecord = -1
	r.LazyQuotes = true

	m := make(NmapServices)

	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if len(rec) < 2 {
			continue
		}
		m[rec[1]] = rec[0]
	}

	return m, nil
}
