package containers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// memEngine is a Docker engine in memory: enough for one port action.
type memEngine struct {
	Engine // the rest is not called
	cs     []Container
	set    []Port
}

func (m *memEngine) Name() string { return "docker" }
func (m *memEngine) List(context.Context) ([]Container, []Network, error) {
	return m.cs, nil, nil
}
func (m *memEngine) Inspect(_ context.Context, id string) (*Container, error) {
	for _, c := range m.cs {
		if c.ID == id || c.Name == id {
			c := c
			return &c, nil
		}
	}
	return nil, os.ErrNotExist
}
func (m *memEngine) SetPorts(_ context.Context, id string, ports []Port) error {
	m.set = ports
	for i := range m.cs {
		if m.cs[i].ID == id {
			m.cs[i].Ports = ports
		}
	}
	return nil
}

func TestPortActionAlsoEditsCompose(t *testing.T) {
	file := filepath.Join(t.TempDir(), "compose.yaml")
	_ = os.WriteFile(file, []byte("services:\n  db:\n    image: mongo\n    ports:\n      - \"27017:27017\"\n"), 0o644)
	e := &memEngine{cs: []Container{
		{Engine: "docker", ID: "a1", Name: "shop-db-1", Running: true, Project: "shop", ComposeService: "db", ComposeFiles: []string{file},
			Ports: []Port{{HostPort: 27017, ContainerPort: 27017, Proto: "tcp"}}, Networks: []Endpoint{{Network: "shop_default"}}},
		{Engine: "docker", ID: "b2", Name: "shop-api-1", Running: true, Networks: []Endpoint{{Network: "shop_default"}}},
		{Engine: "docker", ID: "c3", Name: "loner", Running: true, Networks: []Endpoint{{Network: "bridge"}},
			Ports: []Port{{HostPort: 6379, ContainerPort: 6379, Proto: "tcp"}}},
	}}
	m := NewManager([]Engine{e}, false, quiet())
	ctx := context.Background()

	plan, err := m.PlanPort(ctx, "docker", "a1", 27017, "tcp", PortRemove)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(plan.Reach, ",") != "db:27017,shop-db-1:27017" || strings.Join(plan.Siblings, ",") != "shop-api-1" || !plan.Recreate ||
		plan.Compose == nil || !plan.Compose.OK || len(plan.Ports) != 0 {
		t.Fatalf("plan %+v compose %+v", plan, plan.Compose)
	}
	if b, _ := os.ReadFile(file); !strings.Contains(string(b), "27017") {
		t.Fatal("planning wrote the file")
	}

	c, plan, err := m.PortAction(ctx, "docker", "a1", 27017, "tcp", PortLocal, true)
	if err != nil || len(e.set) != 1 || e.set[0].HostIP != "127.0.0.1" || c.Ports[0].HostIP != "127.0.0.1" {
		t.Fatalf("local: %+v %v %v", c, e.set, err)
	}
	if b, _ := os.ReadFile(file); !plan.Compose.Written || !strings.Contains(string(b), `"127.0.0.1:27017:27017"`) {
		t.Errorf("compose not written: %+v\n%s", plan.Compose, b)
	}

	// Without compose=1 the file stays and the reason says so.
	_, plan, err = m.PortAction(ctx, "docker", "a1", 27017, "tcp", PortPublic, false)
	if b, _ := os.ReadFile(file); err != nil || plan.Compose.Written || !strings.Contains(string(b), "127.0.0.1") || !strings.Contains(plan.Compose.Reason, "you chose") {
		t.Errorf("public without compose: %+v %v", plan.Compose, err)
	}

	// On the default bridge nobody finds it by name.
	if p, _ := m.PlanPort(ctx, "docker", "c3", 6379, "tcp", PortRemove); !p.DefaultBridge || len(p.Reach) != 0 || p.Compose != nil {
		t.Errorf("default bridge: %+v", p)
	}
	if _, err := m.PlanPort(ctx, "docker", "c3", 1234, "tcp", PortRemove); err == nil {
		t.Error("an unpublished port was planned")
	}
	ro := NewManager([]Engine{e}, true, quiet())
	if _, _, err := ro.PortAction(ctx, "docker", "a1", 27017, "tcp", PortRemove, true); err != ErrReadOnly {
		t.Errorf("read-only: %v", err)
	}
}
