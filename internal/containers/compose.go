package containers

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// A port change made through the Docker API lasts only until the next
// "docker compose up", which puts back whatever the compose file says. So
// when a container belongs to a Compose project, the same change is made in
// its compose file: only the line (or lines) of that one port, so comments,
// order and formatting stay as they were. Anything the editor cannot change
// with certainty (a variable, a range, a flow-style list) is left alone and
// the reason is given instead, with the line to write by hand.

// ComposeEdit says what a port change does to a compose file.
type ComposeEdit struct {
	File    string   `json:"file,omitempty"`
	Service string   `json:"service,omitempty"`
	Line    int      `json:"line,omitempty"`   // first changed line, 1-based
	Before  []string `json:"before,omitempty"` // the lines as they are
	After   []string `json:"after,omitempty"`  // the lines as they will be (none when removed)
	OK      bool     `json:"ok"`               // the edit can be (or was) made
	Written bool     `json:"written"`
	Reason  string   `json:"reason,omitempty"` // why not, when !OK
	Manual  string   `json:"manual,omitempty"` // what to write by hand instead
}

// Port actions.
const (
	PortLocal  = "local"  // published on 127.0.0.1 only
	PortPublic = "public" // published on every address
	PortRemove = "remove" // not published
)

// ApplyPortAction returns the ports after one action on host port
// hostPort/proto, and an error when the container does not publish it.
func ApplyPortAction(ports []Port, hostPort int, proto, action string) ([]Port, error) {
	var out []Port
	found, seen := false, map[string]bool{}
	for _, p := range ports {
		if p.HostPort != hostPort || p.Proto != proto {
			out = append(out, p)
			continue
		}
		found = true
		switch action {
		case PortRemove:
			continue
		case PortLocal:
			p.HostIP = "127.0.0.1"
		case PortPublic:
			p.HostIP = ""
		default:
			return nil, fmt.Errorf("unknown port action %q", action)
		}
		p.Inherited = false
		if k := p.String(); !seen[k] { // 0.0.0.0 and [::] become one
			seen[k] = true
			out = append(out, p)
		}
	}
	if !found {
		return nil, fmt.Errorf("the container does not publish host port %d/%s", hostPort, proto)
	}
	return out, nil
}

// ComposePortEdit works out (and with write, makes) the change to the
// compose file of service that matches action on host port hostPort/proto.
// files are the project's config files as Compose recorded them.
func ComposePortEdit(files []string, service string, hostPort, containerPort int, proto, action string, write bool) ComposeEdit {
	e := ComposeEdit{Service: service, Manual: manualLine(hostPort, containerPort, proto, action)}
	if service == "" || len(files) == 0 {
		e.Reason = "Compose did not record which file and service this container comes from"
		return e
	}
	var firstErr string
	for _, f := range files {
		r := editFile(f, service, hostPort, proto, action, write)
		if r.OK || r.Reason != errNotHere {
			r.Service, r.Manual = service, e.Manual
			return r
		}
		if firstErr == "" && r.File != "" {
			firstErr = r.File
		}
	}
	e.File = files[0]
	e.Reason = fmt.Sprintf("the compose file does not list host port %d/%s for %s (it may come from a variable, an override file or the command line)", hostPort, proto, service)
	return e
}

const errNotHere = "not here"

func manualLine(hostPort, containerPort int, proto, action string) string {
	suffix := ""
	if proto == "udp" {
		suffix = "/udp"
	}
	switch action {
	case PortLocal:
		return fmt.Sprintf(`- "127.0.0.1:%d:%d%s"`, hostPort, containerPort, suffix)
	case PortPublic:
		return fmt.Sprintf(`- "%d:%d%s"`, hostPort, containerPort, suffix)
	}
	return fmt.Sprintf("delete the %d:%d%s line under ports:", hostPort, containerPort, suffix)
}

func editFile(path, service string, hostPort int, proto, action string, write bool) ComposeEdit {
	e := ComposeEdit{File: path}
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".yml" && ext != ".yaml" {
		e.Reason = "it is not a .yml or .yaml file"
		return e
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			e.Reason = "SkyGuard cannot see this file (when it runs in a container, mount the project folder into it to let it edit the file)"
		} else {
			e.Reason = err.Error()
		}
		return e
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		e.Reason = "it is not a regular compose file"
		return e
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		e.Reason = "SkyGuard cannot read this file: " + err.Error()
		return e
	}
	lines := strings.Split(string(raw), "\n")
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil || len(doc.Content) == 0 {
		e.Reason = "the file is not valid YAML"
		return e
	}
	svc := mapGet(mapGet(doc.Content[0], "services"), service)
	if svc == nil {
		e.Reason = errNotHere
		return e
	}
	portsKey, ports := mapGetKey(svc, "ports")
	if ports == nil || ports.Kind != yaml.SequenceNode {
		e.Reason = errNotHere
		return e
	}
	if ports.Style&yaml.FlowStyle != 0 {
		e.Reason = "its ports are written as one [ … ] list on a line"
		return e
	}
	var items []*yaml.Node
	for _, it := range ports.Content {
		ok, why := matches(it, hostPort, proto)
		if why != "" {
			e.Reason = why
			return e
		}
		if ok {
			items = append(items, it)
		}
	}
	if len(items) == 0 {
		e.Reason = errNotHere
		return e
	}

	// Each change touches whole lines; they are applied from the bottom up so
	// the line numbers above stay right.
	type change struct {
		from, to int // 0-based, inclusive
		repl     []string
	}
	var changes []change
	removeAll := action == PortRemove && len(items) == len(ports.Content)
	for _, it := range items {
		from, to := it.Line-1, lastLine(it)-1
		if from < 0 || to >= len(lines) {
			e.Reason = "the file changed while it was read"
			return e
		}
		if !ownLine(lines[from], it) {
			e.Reason = fmt.Sprintf("line %d holds more than this port", it.Line)
			return e
		}
		var repl []string
		switch {
		case action == PortRemove:
			repl = nil
		case it.Kind == yaml.ScalarNode:
			l, ok := rewriteScalar(lines[from], it, action)
			if !ok {
				e.Reason = fmt.Sprintf("line %d is not written the way SkyGuard expects", it.Line)
				return e
			}
			repl = []string{l}
		default: // the long syntax: a mapping with published, target, host_ip
			r, ok := rewriteLong(lines, it, action)
			if !ok {
				e.Reason = fmt.Sprintf("the port at line %d is not written the way SkyGuard expects", it.Line)
				return e
			}
			repl = r
		}
		changes = append(changes, change{from, to, repl})
	}
	if removeAll {
		// "ports:" with nothing under it would be null; take the key away too,
		// when it sits on a line of its own.
		k := portsKey.Line - 1
		if strings.TrimSpace(stripComment(lines[k])) == "ports:" {
			changes = append(changes, change{k, k, nil})
		}
	}
	// bottom up
	for i := 0; i < len(changes); i++ {
		for j := i + 1; j < len(changes); j++ {
			if changes[j].from > changes[i].from {
				changes[i], changes[j] = changes[j], changes[i]
			}
		}
	}
	out := append([]string(nil), lines...)
	first := len(lines)
	for _, c := range changes {
		e.Before = append(append([]string(nil), lines[c.from:c.to+1]...), e.Before...)
		e.After = append(append([]string(nil), c.repl...), e.After...)
		out = append(out[:c.from], append(append([]string(nil), c.repl...), out[c.to+1:]...)...)
		if c.from < first {
			first = c.from
		}
	}
	e.Line = first + 1
	text := strings.Join(out, "\n")

	// Read it back: the service must still be there and the port must now
	// read as intended, or nothing is written.
	var check yaml.Node
	if err := yaml.Unmarshal([]byte(text), &check); err != nil || len(check.Content) == 0 {
		e.Reason = "the edited file would not be valid YAML"
		return e
	}
	csvc := mapGet(mapGet(check.Content[0], "services"), service)
	if csvc == nil {
		e.Reason = "the edited file would lose the service"
		return e
	}
	if _, cp := mapGetKey(csvc, "ports"); cp != nil {
		for _, it := range cp.Content {
			ok, _ := matches(it, hostPort, proto)
			if !ok {
				continue
			}
			ip := hostIPOf(it)
			if action == PortRemove || (action == PortLocal && ip != "127.0.0.1") || (action == PortPublic && ip != "") {
				e.Reason = "the edited file would not say what was asked"
				return e
			}
		}
	}
	e.OK = true
	if !write {
		return e
	}
	if err := os.WriteFile(path+".skyguard.bak", raw, info.Mode().Perm()); err != nil {
		e.OK, e.Reason = false, "cannot write a backup next to the file: "+err.Error()
		return e
	}
	if err := os.WriteFile(path, []byte(text), info.Mode().Perm()); err != nil {
		e.OK, e.Reason = false, "cannot write the file: "+err.Error()
		return e
	}
	e.Written = true
	return e
}

func mapGetKey(m *yaml.Node, key string) (k, v *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

func mapGet(m *yaml.Node, key string) *yaml.Node { _, v := mapGetKey(m, key); return v }

// shortPort splits the short syntax [ip:][host:]container[/proto].
type shortPort struct {
	ip, host, container, proto string
}

func parseShort(s string) (shortPort, bool) {
	p := shortPort{proto: "tcp"}
	if i := strings.LastIndex(s, "/"); i >= 0 {
		p.proto, s = strings.ToLower(s[i+1:]), s[:i]
	}
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]:")
		if end < 0 {
			return p, false
		}
		p.ip, s = s[1:end], s[end+2:]
		if strings.Count(s, ":") != 1 {
			return p, false
		}
	}
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 1:
		p.container = parts[0]
	case 2:
		p.host, p.container = parts[0], parts[1]
	case 3:
		if p.ip != "" {
			return p, false
		}
		p.ip, p.host, p.container = parts[0], parts[1], parts[2]
	default:
		return p, false
	}
	return p, true
}

// matches says whether a ports item publishes hostPort/proto; why is set
// when the item cannot be read with certainty and might be the one.
func matches(it *yaml.Node, hostPort int, proto string) (ok bool, why string) {
	want := strconv.Itoa(hostPort)
	switch it.Kind {
	case yaml.ScalarNode:
		p, parsed := parseShort(it.Value)
		if strings.Contains(it.Value, "$") {
			if strings.Contains(it.Value, want) {
				return false, fmt.Sprintf("line %d takes the port from a variable (%s)", it.Line, it.Value)
			}
			return false, ""
		}
		if !parsed {
			return false, ""
		}
		if strings.Contains(p.host, "-") {
			if lo, hi, ok := splitRange(p.host); ok && hostPort >= lo && hostPort <= hi && p.proto == proto {
				return false, fmt.Sprintf("line %d publishes a range of ports (%s)", it.Line, it.Value)
			}
			return false, ""
		}
		return p.host == want && p.proto == proto, ""
	case yaml.MappingNode:
		pub := mapGet(it, "published")
		pr := "tcp"
		if n := mapGet(it, "protocol"); n != nil {
			pr = strings.ToLower(n.Value)
		}
		if pub == nil || pr != proto {
			return false, ""
		}
		if strings.Contains(pub.Value, "$") || strings.Contains(pub.Value, "-") {
			if strings.Contains(pub.Value, want) {
				return false, fmt.Sprintf("the port at line %d is a variable or a range", it.Line)
			}
			return false, ""
		}
		return pub.Value == want, ""
	}
	return false, ""
}

func splitRange(s string) (lo, hi int, ok bool) {
	a, b, found := strings.Cut(s, "-")
	if !found {
		return 0, 0, false
	}
	x, err1 := strconv.Atoi(a)
	y, err2 := strconv.Atoi(b)
	return x, y, err1 == nil && err2 == nil
}

func hostIPOf(it *yaml.Node) string {
	ip := ""
	if it.Kind == yaml.ScalarNode {
		p, _ := parseShort(it.Value)
		ip = p.ip
	} else if n := mapGet(it, "host_ip"); n != nil {
		ip = n.Value
	}
	if ip == "0.0.0.0" || ip == "::" {
		ip = ""
	}
	return ip
}

// ownLine reports whether a list item starts its line as "- item", so
// whole lines can be replaced or removed.
func ownLine(line string, it *yaml.Node) bool {
	col := it.Column - 1
	if it.Kind == yaml.MappingNode && len(it.Content) > 0 {
		col = it.Content[0].Column - 1
	}
	return col > 0 && col <= len(line) && strings.TrimSpace(line[:col]) == "-"
}

// lastLine is the last line a node's value occupies.
func lastLine(n *yaml.Node) int {
	l := n.Line
	for _, c := range n.Content {
		if x := lastLine(c); x > l {
			l = x
		}
	}
	return l
}

func stripComment(l string) string {
	if i := strings.Index(l, " #"); i >= 0 {
		return l[:i]
	}
	return l
}

// rewriteScalar replaces the short-syntax item on its line, keeping the
// indent, the dash and a trailing comment.
func rewriteScalar(line string, it *yaml.Node, action string) (string, bool) {
	col := it.Column - 1
	if col < 0 || col >= len(line) {
		return "", false
	}
	var token string
	switch it.Style {
	case yaml.DoubleQuotedStyle:
		token = `"` + it.Value + `"`
	case yaml.SingleQuotedStyle:
		token = `'` + it.Value + `'`
	case 0:
		token = it.Value
	default:
		return "", false
	}
	if !strings.HasPrefix(line[col:], token) {
		return "", false
	}
	p, ok := parseShort(it.Value)
	if !ok {
		return "", false
	}
	switch action {
	case PortLocal:
		p.ip = "127.0.0.1"
	case PortPublic:
		p.ip = ""
	}
	v := p.host + ":" + p.container
	if p.ip != "" {
		ip := p.ip
		if strings.Contains(ip, ":") {
			ip = "[" + ip + "]"
		}
		v = ip + ":" + v
	}
	if p.proto != "tcp" || strings.Contains(it.Value, "/") {
		v += "/" + p.proto
	}
	// always quoted: Compose advises it, a bare 22:22 is a number in YAML 1.1
	return line[:col] + `"` + v + `"` + line[col+len(token):], true
}

// rewriteLong sets or clears host_ip in a long-syntax item.
func rewriteLong(lines []string, it *yaml.Node, action string) ([]string, bool) {
	from, to := it.Line-1, lastLine(it)-1
	out := append([]string(nil), lines[from:to+1]...)
	k, v := mapGetKey(it, "host_ip")
	if k != nil {
		i := k.Line - 1 - from
		if action == PortPublic && i == 0 {
			return nil, false // host_ip on the dash line: removing it would take the dash
		}
		if action == PortPublic {
			return append(out[:i:i], out[i+1:]...), true
		}
		col := v.Column - 1
		if col < 0 || col >= len(out[i]) {
			return nil, false
		}
		end := col + len(v.Value)
		if v.Style == yaml.DoubleQuotedStyle || v.Style == yaml.SingleQuotedStyle {
			end += 2
		}
		if end > len(out[i]) {
			return nil, false
		}
		out[i] = out[i][:col] + "127.0.0.1" + out[i][end:]
		return out, true
	}
	if action == PortPublic {
		return out, true // already on every address
	}
	// a new host_ip line, indented like the item's other keys, after the first one
	first := it.Content[0]
	indent := strings.Repeat(" ", first.Column-1)
	i := first.Line - 1 - from
	return append(out[:i+1:i+1], append([]string{indent + "host_ip: 127.0.0.1"}, out[i+1:]...)...), true
}
