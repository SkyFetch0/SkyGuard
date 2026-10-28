package containers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const composeFile = `# the shop
services:
  mongo:
    image: mongo:7
    ports:
      - "27017:27017"   # database
      - 28017:28017
    volumes:
      - data:/data/db
  es:
    image: elasticsearch:8
    ports:
      - '9200:9200'
      - "9300:9300/tcp"
  kibana:
    image: kibana:8
    ports:
      - target: 5601
        published: 5601
        protocol: tcp
  grafana:
    image: grafana
    ports:
      - target: 3000
        published: "3000"
        host_ip: 0.0.0.0
  web:
    ports: ["8080:80"]
  env:
    ports:
      - "${PG_PORT:-5432}:5432"
  dns:
    ports:
      - "53:53/udp"
volumes:
  data:
`

func writeCompose(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "docker-compose.yml")
	if err := os.WriteFile(p, []byte(composeFile), 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestComposeLocalOnly(t *testing.T) {
	p := writeCompose(t)
	e := ComposePortEdit([]string{p}, "mongo", 27017, 27017, "tcp", PortLocal, false)
	if !e.OK || e.Line != 6 || e.After[0] != `      - "127.0.0.1:27017:27017"   # database` {
		t.Fatalf("%+v", e)
	}
	if b, _ := os.ReadFile(p); string(b) != composeFile {
		t.Fatal("a preview wrote the file")
	}
	e = ComposePortEdit([]string{p}, "mongo", 27017, 27017, "tcp", PortLocal, true)
	b, _ := os.ReadFile(p)
	if !e.Written || !strings.Contains(string(b), `- "127.0.0.1:27017:27017"   # database`) || !strings.Contains(string(b), "# the shop") {
		t.Fatalf("%+v\n%s", e, b)
	}
	if bak, _ := os.ReadFile(p + ".skyguard.bak"); string(bak) != composeFile {
		t.Error("no backup of the original")
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode changed to %v", fi.Mode())
	}
	// and back again
	e = ComposePortEdit([]string{p}, "mongo", 27017, 27017, "tcp", PortPublic, true)
	if b, _ := os.ReadFile(p); !e.Written || !strings.Contains(string(b), `      - "27017:27017"   # database`) {
		t.Fatalf("%+v\n%s", e, b)
	}
	// an unquoted one gets quotes; a single-quoted one keeps its place
	e = ComposePortEdit([]string{p}, "mongo", 28017, 28017, "tcp", PortLocal, false)
	if !e.OK || e.After[0] != `      - "127.0.0.1:28017:28017"` {
		t.Errorf("%+v", e)
	}
	e = ComposePortEdit([]string{p}, "es", 9300, 9300, "tcp", PortLocal, false)
	if !e.OK || e.After[0] != `      - "127.0.0.1:9300:9300/tcp"` {
		t.Errorf("%+v", e)
	}
}

func TestComposeRemove(t *testing.T) {
	p := writeCompose(t)
	e := ComposePortEdit([]string{p}, "es", 9200, 9200, "tcp", PortRemove, true)
	b, _ := os.ReadFile(p)
	if !e.Written || strings.Contains(string(b), "9200") || !strings.Contains(string(b), "9300:9300") || len(e.After) != 0 {
		t.Fatalf("%+v\n%s", e, b)
	}
	// the last port of a service takes "ports:" with it
	e = ComposePortEdit([]string{p}, "es", 9300, 9300, "tcp", PortRemove, true)
	b, _ = os.ReadFile(p)
	if !e.Written || strings.Contains(string(b), "9300") || strings.Count(string(b), "ports:") != 6 {
		t.Fatalf("%+v\n%s", e, b)
	}
	if !strings.Contains(string(b), "  es:\n    image: elasticsearch:8\n  kibana:") {
		t.Errorf("es block:\n%s", b)
	}
	// a long-syntax item goes as a whole
	e = ComposePortEdit([]string{p}, "kibana", 5601, 5601, "tcp", PortRemove, true)
	b, _ = os.ReadFile(p)
	if !e.Written || strings.Contains(string(b), "5601") || len(e.Before) != 4 {
		t.Fatalf("%+v\n%s", e, b)
	}
}

func TestComposeLongSyntax(t *testing.T) {
	p := writeCompose(t)
	e := ComposePortEdit([]string{p}, "kibana", 5601, 5601, "tcp", PortLocal, true)
	b, _ := os.ReadFile(p)
	if !e.Written || !strings.Contains(string(b), "      - target: 5601\n        host_ip: 127.0.0.1\n        published: 5601") {
		t.Fatalf("%+v\n%s", e, b)
	}
	e = ComposePortEdit([]string{p}, "grafana", 3000, 3000, "tcp", PortLocal, true)
	b, _ = os.ReadFile(p)
	if !e.Written || !strings.Contains(string(b), "        host_ip: 127.0.0.1\n  web:") {
		t.Fatalf("%+v\n%s", e, b)
	}
	e = ComposePortEdit([]string{p}, "grafana", 3000, 3000, "tcp", PortPublic, true)
	b, _ = os.ReadFile(p)
	if !e.Written || !strings.Contains(string(b), `        published: "3000"`+"\n  web:") {
		t.Fatalf("%+v\n%s", e, b)
	}
}

func TestComposeLeavesUnclearCasesAlone(t *testing.T) {
	p := writeCompose(t)
	for _, c := range []struct {
		svc   string
		port  int
		proto string
		want  string
	}{
		{"web", 8080, "tcp", "one [ … ] list"},
		{"env", 5432, "tcp", "variable"},
		{"dns", 53, "tcp", "does not list"}, // udp only
		{"nope", 1, "tcp", "does not list"},
	} {
		e := ComposePortEdit([]string{p}, c.svc, c.port, c.port, c.proto, PortLocal, true)
		if e.OK || e.Written || !strings.Contains(e.Reason, c.want) || e.Manual == "" {
			t.Errorf("%s: %+v", c.svc, e)
		}
	}
	if b, _ := os.ReadFile(p); string(b) != composeFile {
		t.Error("the file was changed")
	}
	if e := ComposePortEdit([]string{p}, "dns", 53, 53, "udp", PortLocal, false); !e.OK || e.After[0] != `      - "127.0.0.1:53:53/udp"` {
		t.Errorf("udp: %+v", e)
	}
	// an override file that does not mention the port is skipped for the one that does
	o := filepath.Join(filepath.Dir(p), "docker-compose.override.yml")
	_ = os.WriteFile(o, []byte("services:\n  mongo:\n    restart: always\n"), 0o644)
	if e := ComposePortEdit([]string{o, p}, "mongo", 27017, 27017, "tcp", PortLocal, false); !e.OK || e.File != p {
		t.Errorf("override: %+v", e)
	}
	if e := ComposePortEdit([]string{"/nonexistent/docker-compose.yml"}, "mongo", 27017, 27017, "tcp", PortLocal, false); e.OK || !strings.Contains(e.Reason, "cannot see") {
		t.Errorf("missing file: %+v", e)
	}
}

func TestApplyPortAction(t *testing.T) {
	ports := []Port{{HostPort: 27017, ContainerPort: 27017, Proto: "tcp"}, {HostIP: "::", HostPort: 27017, ContainerPort: 27017, Proto: "tcp"}, {HostPort: 8080, ContainerPort: 80, Proto: "tcp"}}
	got, err := ApplyPortAction(ports, 27017, "tcp", PortLocal)
	if err != nil || len(got) != 2 || got[0].HostIP != "127.0.0.1" || got[1].HostPort != 8080 {
		t.Fatalf("%+v %v", got, err)
	}
	if got, _ := ApplyPortAction(ports, 27017, "tcp", PortRemove); len(got) != 1 {
		t.Errorf("remove: %+v", got)
	}
	if _, err := ApplyPortAction(ports, 9999, "tcp", PortRemove); err == nil {
		t.Error("an unpublished port was accepted")
	}
}
