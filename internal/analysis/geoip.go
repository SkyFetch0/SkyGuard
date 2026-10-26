package analysis

import (
	"net"

	"github.com/oschwald/geoip2-golang"
)

// GeoIPService wraps a geoip2 reader with a graceful disabled mode.
type GeoIPService struct {
	reader *geoip2.Reader
}

// GeoInfo holds geographic information for an IP address.
type GeoInfo struct {
	Country     string
	CountryCode string
	City        string
}

// NewGeoIPService opens the MaxMind database at dbPath. When enabled is false
// a disabled service is returned. When the database cannot be opened the
// service is also disabled and the error is returned so the caller can warn;
// it is never fatal.
func NewGeoIPService(dbPath string, enabled bool) (*GeoIPService, error) {
	if !enabled || dbPath == "" {
		return &GeoIPService{}, nil
	}
	reader, err := geoip2.Open(dbPath)
	if err != nil {
		return &GeoIPService{}, err
	}
	return &GeoIPService{reader: reader}, nil
}

// Enabled reports whether lookups return real data.
func (g *GeoIPService) Enabled() bool { return g != nil && g.reader != nil }

// Lookup returns geographic info for the given IP string. An empty GeoInfo is
// returned when the service is disabled or the IP is not in the database.
func (g *GeoIPService) Lookup(ipStr string) GeoInfo {
	if !g.Enabled() {
		return GeoInfo{}
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return GeoInfo{}
	}
	record, err := g.reader.City(ip)
	if err != nil {
		return GeoInfo{}
	}
	return GeoInfo{
		Country:     record.Country.Names["en"],
		CountryCode: record.Country.IsoCode,
		City:        record.City.Names["en"],
	}
}

// Close releases the underlying database reader.
func (g *GeoIPService) Close() {
	if g.reader != nil {
		g.reader.Close()
	}
}
