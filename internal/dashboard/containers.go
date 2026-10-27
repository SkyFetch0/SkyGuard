package dashboard

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/skyguard/skyguard/internal/containers"
	"github.com/skyguard/skyguard/internal/netutil"
)

// SetContainers enables the containers screen. Call before Start.
func (d *Dashboard) SetContainers(m *containers.Manager) { d.ctr = m }

func (d *Dashboard) containerRoutes(api *http.ServeMux) {
	api.HandleFunc("GET /api/containers", d.handleContainers)
	api.HandleFunc("GET /api/containers/inspect", d.handleContainerInspect)
	api.HandleFunc("POST /api/containers/action", d.csrf(d.containerChange(d.doContainerAction)))
	api.HandleFunc("POST /api/containers/connect", d.csrf(d.containerChange(d.doContainerConnect)))
	api.HandleFunc("POST /api/containers/disconnect", d.csrf(d.containerChange(d.doContainerDisconnect)))
	api.HandleFunc("POST /api/containers/ports", d.csrf(d.containerChange(d.doContainerPorts)))
	api.HandleFunc("POST /api/containers/settings", d.csrf(d.containerChange(d.doContainerSettings)))
	api.HandleFunc("POST /api/containers/networks", d.csrf(d.handleCreateNetwork))
}

func (d *Dashboard) reservedPorts() []containers.Reserved {
	if d.ctr == nil || d.ctr.Reserved == nil {
		return nil
	}
	return d.ctr.Reserved()
}

// handleContainers lists every engine's containers and networks and who
// holds each host port.
func (d *Dashboard) handleContainers(w http.ResponseWriter, r *http.Request) {
	if d.ctr == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	snap := d.ctr.Snapshot(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":      true,
		"read_only":    snap.ReadOnly,
		"engines":      snap.Engines,
		"containers":   snap.Containers,
		"networks":     snap.Networks,
		"host_ports":   containers.HostPorts(snap, d.reservedPorts()),
		"ban_coverage": d.banCoverage(),
	})
}

// dockerCoverage is implemented by the iptables firewall.
type dockerCoverage interface{ CoversDocker() (docker, covered bool) }

// banCoverage says whether a ban also stops traffic to published container
// ports. Docker forwards it through FORWARD, past INPUT, so only a hook in
// DOCKER-USER covers it; Incus proxy devices accept on the host, through INPUT.
func (d *Dashboard) banCoverage() map[string]any {
	out := map[string]any{"method": d.fw.Method()}
	if c, ok := d.fw.(dockerCoverage); ok {
		docker, covered := c.CoversDocker()
		out["docker_chain"], out["docker_covered"] = docker, covered
	}
	return out
}

func (d *Dashboard) handleContainerInspect(w http.ResponseWriter, r *http.Request) {
	if d.ctr == nil {
		writeError(w, http.StatusNotFound, "container management is not enabled")
		return
	}
	q := r.URL.Query()
	c, err := d.ctr.Inspect(r.Context(), q.Get("engine"), q.Get("id"))
	if err != nil {
		writeContainerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// containerOp is one change; it returns the container as it is afterwards.
type containerOp func(ctx context.Context, engine, id string, form func(string) string) (*containers.Container, error)

// containerChange runs a change with its own deadline: a port change that
// recreates a container must finish (or roll back) even if the browser
// navigates away, and may take longer than the server's write timeout.
func (d *Dashboard) containerChange(op containerOp) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.ctr == nil {
			writeError(w, http.StatusNotFound, "container management is not enabled")
			return
		}
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid form")
			return
		}
		engine, id := r.PostForm.Get("engine"), strings.TrimSpace(r.PostForm.Get("id"))
		if engine == "" || id == "" {
			writeError(w, http.StatusBadRequest, "engine and id are required")
			return
		}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(4 * time.Minute))
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Minute)
		defer cancel()
		d.logger.Info("container change requested", "remote", netutil.HostIP(r.RemoteAddr), "path", r.URL.Path, "engine", engine, "id", id)
		c, err := op(ctx, engine, id, func(k string) string { return strings.TrimSpace(r.PostForm.Get(k)) })
		if err != nil {
			writeContainerError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, c)
	}
}

var errBadRequest = errors.New("bad request")

type badRequest struct{ msg string }

func (b badRequest) Error() string { return b.msg }
func (b badRequest) Unwrap() error { return errBadRequest }

func writeContainerError(w http.ResponseWriter, err error) {
	var api *containers.APIError
	switch {
	case errors.Is(err, errBadRequest):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, containers.ErrReadOnly):
		writeError(w, http.StatusForbidden, err.Error())
	case errors.As(err, &api) && api.Status == http.StatusNotFound:
		writeError(w, http.StatusNotFound, err.Error())
	default:
		writeError(w, http.StatusConflict, err.Error())
	}
}

func (d *Dashboard) doContainerAction(ctx context.Context, engine, id string, form func(string) string) (*containers.Container, error) {
	return d.ctr.Action(ctx, engine, id, form("action"))
}

func (d *Dashboard) doContainerConnect(ctx context.Context, engine, id string, form func(string) string) (*containers.Container, error) {
	return d.ctr.Connect(ctx, engine, id, form("network"), parseBool(form("create")))
}

func (d *Dashboard) doContainerDisconnect(ctx context.Context, engine, id string, form func(string) string) (*containers.Container, error) {
	return d.ctr.Disconnect(ctx, engine, id, form("network"))
}

func (d *Dashboard) doContainerPorts(ctx context.Context, engine, id string, form func(string) string) (*containers.Container, error) {
	ports, err := containers.ParsePorts(form("ports"))
	if err != nil {
		return nil, badRequest{err.Error()}
	}
	return d.ctr.SetPorts(ctx, engine, id, ports)
}

// doContainerSettings takes restart, memory_mb and cpus; a field left out
// is left as it is, and 0 removes a limit.
func (d *Dashboard) doContainerSettings(ctx context.Context, engine, id string, form func(string) string) (*containers.Container, error) {
	var s containers.Settings
	if v := form("restart"); v != "" {
		s.Restart = &v
	}
	if v := form("memory_mb"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return nil, badRequest{"memory_mb must be a whole number of megabytes (0 = no limit)"}
		}
		s.MemoryMB = &n
	}
	if v := form("cpus"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f < 0 || f > 1024 {
			return nil, badRequest{"cpus must be a number of CPUs (0 = no limit)"}
		}
		s.CPUs = &f
	}
	return d.ctr.Update(ctx, engine, id, s)
}

func (d *Dashboard) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	if d.ctr == nil {
		writeError(w, http.StatusNotFound, "container management is not enabled")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid form")
		return
	}
	engine, name := r.PostForm.Get("engine"), strings.TrimSpace(r.PostForm.Get("name"))
	if err := d.ctr.CreateNetwork(r.Context(), engine, name); err != nil {
		writeContainerError(w, err)
		return
	}
	d.logger.Info("network created via dashboard", "remote", netutil.HostIP(r.RemoteAddr), "engine", engine, "name", name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name})
}
