package dashboard

import (
	"net/http"

	"github.com/skyguard/skyguard/internal/inventory"
	"github.com/skyguard/skyguard/internal/netutil"
)

// SetSoftware enables the software inventory screen. Call before Start.
func (d *Dashboard) SetSoftware(m *inventory.Manager) { d.inv = m }

func (d *Dashboard) softwareRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/software", d.handleSoftware)
	api.HandleFunc("GET /api/software/target", d.handleSoftwareTarget)
	api.HandleFunc("POST /api/software/scan", d.csrf(d.softwareAction("scan", func() error { return d.inv.Scan() })))
	api.HandleFunc("POST /api/software/check", d.csrf(d.softwareAction("check", func() error { return d.inv.Check() })))
	api.HandleFunc("POST /api/software/osv", d.csrf(d.handleSoftwareOSV))
}

func (d *Dashboard) handleSoftware(w http.ResponseWriter, _ *http.Request) {
	if d.inv == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "targets": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, d.inv.View())
}

func (d *Dashboard) handleSoftwareTarget(w http.ResponseWriter, r *http.Request) {
	if d.inv == nil {
		writeError(w, http.StatusNotFound, "the software inventory is not set up")
		return
	}
	t, ok := d.inv.Target(r.URL.Query().Get("key"))
	if !ok {
		writeError(w, http.StatusNotFound, "not scanned")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (d *Dashboard) softwareAction(what string, fn func() error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.inv == nil {
			writeError(w, http.StatusNotFound, "the software inventory is not set up")
			return
		}
		if err := fn(); err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		d.logger.Info("software "+what+" started from the dashboard", "remote", netutil.HostIP(r.RemoteAddr))
		writeJSON(w, http.StatusOK, d.inv.View())
	}
}

// handleSoftwareOSV takes enabled: whether package names and versions may
// be sent to OSV.dev.
func (d *Dashboard) handleSoftwareOSV(w http.ResponseWriter, r *http.Request) {
	if d.inv == nil {
		writeError(w, http.StatusNotFound, "the software inventory is not set up")
		return
	}
	on := r.FormValue("enabled") == "1"
	if err := d.inv.SetOSV(on); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	d.logger.Info("OSV.dev checks switched from the dashboard", "remote", netutil.HostIP(r.RemoteAddr), "enabled", on)
	writeJSON(w, http.StatusOK, d.inv.View())
}
