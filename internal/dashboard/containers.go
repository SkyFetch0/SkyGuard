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
	api.HandleFunc("GET /api/containers/port-plan", d.handlePortPlan)
	api.HandleFunc("POST /api/containers/port", d.csrf(d.handlePortAction))
	api.HandleFunc("POST /api/containers/settings", d.csrf(d.containerChange(d.doContainerSettings)))
	api.HandleFunc("POST /api/containers/networks", d.csrf(d.handleCreateNetwork))
	api.HandleFunc("POST /api/containers/networks/delete", d.csrf(d.handleDeleteNetwork))
	api.HandleFunc("POST /api/containers/engines", d.csrf(d.handleEngineSwitch))
	api.HandleFunc("POST /api/containers/create", d.csrf(d.handleCreateContainer))
	api.HandleFunc("POST /api/containers/remove", d.csrf(d.handleRemoveContainer))
	api.HandleFunc("GET /api/containers/logs", d.handleContainerLogs)
	api.HandleFunc("GET /api/containers/snapshots", d.handleSnapshots)
	api.HandleFunc("POST /api/containers/snapshots", d.csrf(d.containerChange(d.doSnapshot)))
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
		"enabled":      d.ctr.AnyEnabled(),
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

// portActionArgs reads engine, id, host_port, proto and action.
func portActionArgs(get func(string) string) (engine, id string, port int, proto, action string, err error) {
	engine, id, proto, action = get("engine"), strings.TrimSpace(get("id")), get("proto"), get("action")
	if proto == "" {
		proto = "tcp"
	}
	port, perr := strconv.Atoi(get("host_port"))
	switch {
	case engine == "" || id == "":
		err = errors.New("engine and id are required")
	case perr != nil || port < 1 || port > 65535:
		err = errors.New("host_port must be a port number")
	case proto != "tcp" && proto != "udp":
		err = errors.New("proto must be tcp or udp")
	case action != containers.PortLocal && action != containers.PortPublic && action != containers.PortRemove:
		err = errors.New("action must be local, public or remove")
	}
	return
}

// handlePortPlan says what a port action would do, Compose file included.
func (d *Dashboard) handlePortPlan(w http.ResponseWriter, r *http.Request) {
	if d.ctr == nil {
		writeError(w, http.StatusNotFound, "container management is not enabled")
		return
	}
	engine, id, port, proto, action, err := portActionArgs(r.URL.Query().Get)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	plan, err := d.ctr.PlanPort(r.Context(), engine, id, port, proto, action)
	if err != nil {
		writeContainerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

// handlePortAction makes one published port local only (action=local),
// public (public) or unpublished (remove); compose=1 also edits the
// container's Compose file.
func (d *Dashboard) handlePortAction(w http.ResponseWriter, r *http.Request) {
	if d.ctr == nil {
		writeError(w, http.StatusNotFound, "container management is not enabled")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid form")
		return
	}
	get := func(k string) string { return strings.TrimSpace(r.PostForm.Get(k)) }
	engine, id, port, proto, action, err := portActionArgs(get)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(4 * time.Minute))
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Minute)
	defer cancel()
	d.logger.Info("container port change requested", "remote", netutil.HostIP(r.RemoteAddr), "engine", engine, "id", id, "port", port, "proto", proto, "action", action)
	c, plan, err := d.ctr.PortAction(ctx, engine, id, port, proto, action, get("compose") == "1")
	if err != nil {
		writeContainerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"container": c, "plan": plan})
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

// longChange gives a request its own deadline, detached from the browser:
// a pull or a removal must finish even if the tab closes.
func longChange(w http.ResponseWriter, r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(d + time.Minute))
	return context.WithTimeout(context.WithoutCancel(r.Context()), d)
}

func (d *Dashboard) ctrForm(w http.ResponseWriter, r *http.Request) bool {
	if d.ctr == nil {
		writeError(w, http.StatusNotFound, "container management is not available without the dashboard")
		return false
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid form")
		return false
	}
	return true
}

func (d *Dashboard) handleDeleteNetwork(w http.ResponseWriter, r *http.Request) {
	if !d.ctrForm(w, r) {
		return
	}
	engine, name := r.PostForm.Get("engine"), strings.TrimSpace(r.PostForm.Get("name"))
	if err := d.ctr.DeleteNetwork(r.Context(), engine, name); err != nil {
		writeContainerError(w, err)
		return
	}
	d.logger.Info("network deleted via dashboard", "remote", netutil.HostIP(r.RemoteAddr), "engine", engine, "name", name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleEngineSwitch turns Docker or Incus management on or off.
func (d *Dashboard) handleEngineSwitch(w http.ResponseWriter, r *http.Request) {
	if !d.ctrForm(w, r) {
		return
	}
	engine, on := r.PostForm.Get("engine"), parseBool(r.PostForm.Get("enabled"))
	d.logger.Info("container engine switch requested", "remote", netutil.HostIP(r.RemoteAddr), "engine", engine, "enabled", on)
	if err := d.ctr.SetEngineEnabled(r.Context(), engine, on); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "engine": engine, "enabled": on})
}

// handleCreateContainer takes engine, name, image, ports, network, env (one
// KEY=value per line), restart, memory_mb, cpus, vm and start.
func (d *Dashboard) handleCreateContainer(w http.ResponseWriter, r *http.Request) {
	if !d.ctrForm(w, r) {
		return
	}
	f := func(k string) string { return strings.TrimSpace(r.PostForm.Get(k)) }
	spec := containers.CreateSpec{Name: f("name"), Image: f("image"), Network: f("network"), Restart: f("restart"),
		VM: parseBool(f("vm")), Start: !r.PostForm.Has("start") || parseBool(f("start"))}
	var err error
	if spec.Ports, err = containers.ParsePorts(f("ports")); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, line := range strings.Split(r.PostForm.Get("env"), "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		if k, _, ok := strings.Cut(line, "="); !ok || k == "" || strings.ContainsAny(k, " \t") {
			writeError(w, http.StatusBadRequest, "environment lines are KEY=value: "+line)
			return
		}
		spec.Env = append(spec.Env, line)
	}
	if v := f("memory_mb"); v != "" {
		if spec.MemoryMB, err = strconv.ParseInt(v, 10, 64); err != nil || spec.MemoryMB < 0 {
			writeError(w, http.StatusBadRequest, "memory_mb must be a whole number of megabytes")
			return
		}
	}
	if v := f("cpus"); v != "" {
		if spec.CPUs, err = strconv.ParseFloat(v, 64); err != nil || spec.CPUs < 0 || spec.CPUs > 1024 {
			writeError(w, http.StatusBadRequest, "cpus must be a number of CPUs")
			return
		}
	}
	// Pulling an image or downloading an Incus image can take minutes.
	ctx, cancel := longChange(w, r, 15*time.Minute)
	defer cancel()
	d.logger.Info("container create requested", "remote", netutil.HostIP(r.RemoteAddr), "engine", f("engine"), "name", spec.Name, "image", spec.Image)
	c, err := d.ctr.Create(ctx, f("engine"), spec)
	if err != nil && c == nil {
		writeContainerError(w, err)
		return
	}
	resp := map[string]any{"container": c}
	if err != nil {
		resp["warning"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (d *Dashboard) handleRemoveContainer(w http.ResponseWriter, r *http.Request) {
	if !d.ctrForm(w, r) {
		return
	}
	engine, id := r.PostForm.Get("engine"), strings.TrimSpace(r.PostForm.Get("id"))
	ctx, cancel := longChange(w, r, 3*time.Minute)
	defer cancel()
	d.logger.Info("container removal requested", "remote", netutil.HostIP(r.RemoteAddr), "engine", engine, "id", id)
	if err := d.ctr.Remove(ctx, engine, id, parseBool(r.PostForm.Get("volumes"))); err != nil {
		writeContainerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (d *Dashboard) handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	if d.ctr == nil {
		writeError(w, http.StatusNotFound, "container management is not available")
		return
	}
	q := r.URL.Query()
	lines := intParam(q, "lines", 200, 10, 2000)
	out, err := d.ctr.Logs(r.Context(), q.Get("engine"), q.Get("id"), lines)
	if err != nil {
		writeContainerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": lines, "text": out})
}

func (d *Dashboard) handleSnapshots(w http.ResponseWriter, r *http.Request) {
	if d.ctr == nil {
		writeError(w, http.StatusNotFound, "container management is not available")
		return
	}
	q := r.URL.Query()
	snaps, err := d.ctr.Snapshots(r.Context(), q.Get("engine"), q.Get("id"))
	if err != nil {
		writeContainerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, snaps)
}

func (d *Dashboard) doSnapshot(ctx context.Context, engine, id string, form func(string) string) (*containers.Container, error) {
	return d.ctr.SnapshotAction(ctx, engine, id, form("action"), form("name"))
}
