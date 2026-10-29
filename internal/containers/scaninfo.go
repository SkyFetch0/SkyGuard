package containers

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
)

// ScanInfo is what the software inventory needs to know about a container
// or instance. Nothing here is run; it only says where to read.
type ScanInfo struct {
	Engine, ID, Name, Image string
	Kind                    string // container or virtual-machine
	Running                 bool
	PID                     int // its first process on the host, 0 when not running
	WorkingDir              string
	Command                 []string          // entrypoint, then cmd
	Env                     map[string]string // only names ending in _VERSION
	Labels                  map[string]string // only org.opencontainers.image.*
	Self                    bool
}

// ScanInfos lists every container and instance of the enabled engines.
func (m *Manager) ScanInfos(ctx context.Context) ([]ScanInfo, []error) {
	var out []ScanInfo
	var errs []error
	for _, e := range m.active() {
		cs, _, err := e.List(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Name(), err))
			continue
		}
		d, isDocker := e.(*Docker)
		for _, c := range cs {
			si := ScanInfo{Engine: c.Engine, ID: c.ID, Name: c.Name, Image: c.Image, Kind: c.Kind, Running: c.Running, PID: c.PID, Self: c.Self}
			if isDocker {
				if in, err := d.inspect(ctx, c.ID); err == nil {
					si.PID = in.State.Pid
					si.WorkingDir, _ = in.Config["WorkingDir"].(string)
					si.Command = append(strs(in.Config["Entrypoint"]), strs(in.Config["Cmd"])...)
					si.Env = map[string]string{}
					for _, kv := range strs(in.Config["Env"]) {
						if k, v, ok := strings.Cut(kv, "="); ok && strings.HasSuffix(k, "_VERSION") {
							si.Env[k] = v
						}
					}
					si.Labels = map[string]string{}
					if l, ok := in.Config["Labels"].(map[string]any); ok {
						for k, v := range l {
							if s, ok := v.(string); ok && strings.HasPrefix(k, "org.opencontainers.image.") {
								si.Labels[k] = s
							}
						}
					}
				}
			}
			out = append(out, si)
		}
	}
	return out, errs
}

func strs(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ErrNotRegular is returned when a path is not a regular file.
var ErrNotRegular = errors.New("not a regular file")

// ReadFile reads one file from a Docker container, running or not,
// through the Docker API: the daemon resolves the path inside the
// container's own file system. A symbolic link is followed by path only
// (it can never leave the container that way), at most eight times.
func (m *Manager) ReadFile(ctx context.Context, engine, id, p string, max int64) ([]byte, error) {
	e, err := m.engine(engine)
	if err != nil {
		return nil, err
	}
	d, ok := e.(*Docker)
	if !ok {
		return nil, fmt.Errorf("%s: reading files through the API is not supported", engine)
	}
	if max > 30<<20 {
		max = 30 << 20 // the API reply is capped a little above
	}
	p = path.Clean("/" + p)
	for hop := 0; hop < 8; hop++ {
		prefix, err := d.negotiate(ctx)
		if err != nil {
			return nil, err
		}
		resp, err := d.c.do(ctx, "GET", prefix+"/containers/"+url.PathEscape(id)+"/archive", url.Values{"path": {p}}, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("docker: %w", err)
		}
		if resp.status == 404 {
			return nil, fmt.Errorf("%s: %w", p, errNotFound)
		}
		if resp.status != 200 {
			return nil, &APIError{Engine: "docker", Status: resp.status, Message: strings.TrimSpace(string(resp.body))}
		}
		tr := tar.NewReader(bytes.NewReader(resp.body))
		h, err := tr.Next()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		switch h.Typeflag {
		case tar.TypeReg:
			if h.Size > max {
				return nil, fmt.Errorf("%s: larger than %d bytes", p, max)
			}
			return io.ReadAll(io.LimitReader(tr, max))
		case tar.TypeSymlink:
			target := h.Linkname
			if !strings.HasPrefix(target, "/") {
				target = path.Join(path.Dir(p), target)
			}
			p = path.Clean("/" + target)
		default:
			return nil, fmt.Errorf("%s: %w", p, ErrNotRegular)
		}
	}
	return nil, fmt.Errorf("%s: too many symbolic links", p)
}

// errNotFound wraps a missing path, so callers can tell it from a failure.
var errNotFound = errors.New("no such file")

// IsNotFound reports whether err is a missing path from ReadFile.
func IsNotFound(err error) bool { return errors.Is(err, errNotFound) }
