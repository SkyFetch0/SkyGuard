package analysis

import (
	"net"

	"github.com/oschwald/geoip2-golang"
)

// GeoIPService wraps geoip2 reader with graceful disabled mode.
type GeoIPService struct {
	reader  *geoip2.Reader
	enabled bool
}

// GeoInfo holds geographic information for an IP address.
type GeoInfo struct {
	Country     string
	CountryCode string
	City        string
}

// NewGeoIPService creates a GeoIPService. If dbPath is missing or unreadable,
// the service runs in disabled mode without returning an error.
func NewGeoIPService(dbPath string, enabled bool) (*GeoIPService, error) {
	if !enabled || dbPath == "" {
		return &GeoIPService{enabled: false}, nil
	}

	reader, err := geoip2.Open(dbPath)
	if err != nil {
		// Disabled mode – not a fatal error.
		return &GeoIPService{enabled: false}, nil
	}

	return &GeoIPService{reader: reader, enabled: true}, nil
}

// Lookup returns geographic info for the given IP string.
// Returns an empty GeoInfo if the service is disabled or any error occurs.
func (g *GeoIPService) Lookup(ipStr string) *GeoInfo {
	if !g.enabled || g.reader == nil {
		return &GeoInfo{}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return &GeoInfo{}
	}

	record, err := g.reader.City(ip)
	if err != nil {
		return &GeoInfo{}
	}

	city := ""
	if name, ok := record.City.Names["en"]; ok {
		city = name
	}

	return &GeoInfo{
		Country:     record.Country.Names["en"],
		CountryCode: record.Country.IsoCode,
		City:        city,
	}
}

// Close releases the underlying database reader.
func (g *GeoIPService) Close() {
	if g.reader != nil {
		g.reader.Close()
	}
}
