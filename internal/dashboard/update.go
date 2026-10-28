package dashboard

import (
	"context"
	"net/http"
	"time"

	"github.com/skyguard/skyguard/internal/netutil"
	"github.com/skyguard/skyguard/internal/update"
)

// SetUpdater enables the version and updates panel. Call before Start.
func (d *Dashboard) SetUpdater(u *update.Manager) { d.upd = u }

func (d *Dashboard) updateRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/update", d.handleUpdate)
	api.HandleFunc("POST /api/update/check", d.csrf(d.handleUpdateCheck))
	api.HandleFunc("POST /api/update/apply", d.csrf(d.handleUpdateApply))
	api.HandleFunc("POST /api/update/rollback", d.csrf(d.handleUpdateRollback))
}

func (d *Dashboard) handleUpdate(w http.ResponseWriter, _ *http.Request) {
	if d.upd == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "running": map[string]string{"version": Version}})
		return
	}
	writeJSON(w, http.StatusOK, d.upd.View())
}

func (d *Dashboard) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if d.upd == nil {
		writeError(w, http.StatusNotFound, "updates are not set up")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if _, err := d.upd.Check(ctx); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, d.upd.View())
}

func (d *Dashboard) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	if d.upd == nil {
		writeError(w, http.StatusNotFound, "updates are not set up")
		return
	}
	v := r.FormValue("version")
	if err := d.upd.Apply(v); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	d.logger.Info("update started from the dashboard", "remote", netutil.HostIP(r.RemoteAddr), "version", v)
	writeJSON(w, http.StatusOK, d.upd.View())
}

func (d *Dashboard) handleUpdateRollback(w http.ResponseWriter, r *http.Request) {
	if d.upd == nil {
		writeError(w, http.StatusNotFound, "updates are not set up")
		return
	}
	if err := d.upd.Rollback(); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	d.logger.Info("rollback started from the dashboard", "remote", netutil.HostIP(r.RemoteAddr))
	writeJSON(w, http.StatusOK, d.upd.View())
}
