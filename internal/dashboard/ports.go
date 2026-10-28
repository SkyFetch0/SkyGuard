package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/skyguard/skyguard/internal/firewall"
	"github.com/skyguard/skyguard/internal/netutil"
	"github.com/skyguard/skyguard/internal/portrules"
)

// SetPortRules enables the port access rules. Call before Start.
func (d *Dashboard) SetPortRules(m *portrules.Manager, listeners func(context.Context) []portrules.Listener) {
	d.ports, d.portListeners = m, listeners
}

func (d *Dashboard) portRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/ports", d.handlePorts)
	api.HandleFunc("POST /api/ports", d.csrf(d.handleSetPorts))
	api.HandleFunc("POST /api/ports/confirm", d.csrf(d.handleConfirmPorts))
	api.HandleFunc("POST /api/ports/revert", d.csrf(d.handleRevertPorts))
}

func (d *Dashboard) listeners(ctx context.Context) []portrules.Listener {
	if d.portListeners == nil {
		return []portrules.Listener{}
	}
	return d.portListeners(ctx)
}

// handlePorts lists the host's listening ports and the rules guarding them.
func (d *Dashboard) handlePorts(w http.ResponseWriter, r *http.Request) {
	if d.ports == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "reason": "port rules are not set up", "rules": []any{}, "listeners": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, struct {
		portrules.View
		Listeners []portrules.Listener `json:"listeners"`
		ClientIP  string               `json:"client_ip"`
	}{d.ports.View(), d.listeners(r.Context()), netutil.HostIP(r.RemoteAddr)})
}

// handleSetPorts replaces the rule set with the JSON list in "rules".
func (d *Dashboard) handleSetPorts(w http.ResponseWriter, r *http.Request) {
	if d.ports == nil {
		writeError(w, http.StatusNotFound, "port rules are not set up")
		return
	}
	var rules []firewall.PortRule
	if err := json.Unmarshal([]byte(r.FormValue("rules")), &rules); err != nil {
		writeError(w, http.StatusBadRequest, "rules must be a JSON list")
		return
	}
	res, err := d.ports.Set(rules)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, portrules.ErrUnavailable) {
			status = http.StatusConflict
		}
		writeError(w, status, err.Error())
		return
	}
	d.logger.Info("port access rules changed via dashboard", "remote", netutil.HostIP(r.RemoteAddr), "rules", len(rules), "trial", res.Trial)
	writeJSON(w, http.StatusOK, res)
}

func (d *Dashboard) handleConfirmPorts(w http.ResponseWriter, r *http.Request) {
	d.portTrial(w, r, "confirmed", func() error { return d.ports.Confirm() })
}

func (d *Dashboard) handleRevertPorts(w http.ResponseWriter, r *http.Request) {
	d.portTrial(w, r, "reverted", func() error { return d.ports.Revert() })
}

func (d *Dashboard) portTrial(w http.ResponseWriter, r *http.Request, what string, fn func() error) {
	if d.ports == nil {
		writeError(w, http.StatusNotFound, "port rules are not set up")
		return
	}
	if err := fn(); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	d.logger.Info("port access rules "+what+" via dashboard", "remote", netutil.HostIP(r.RemoteAddr))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
