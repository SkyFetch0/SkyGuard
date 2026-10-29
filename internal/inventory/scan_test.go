package inventory

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, p, content string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const dpkgStatus = `Package: nginx
Status: install ok installed
Version: 1.22.1-9+deb12u1
Architecture: amd64

Package: libssl3
Status: install ok installed
Source: openssl (3.0.11-1~deb12u1)
Version: 3.0.11-1~deb12u1

Package: openssl
Status: install ok installed
Version: 3.0.11-1~deb12u1

Package: removed-thing
Status: deinstall ok config-files
Version: 1.0
`

func sampleRoot(t *testing.T) string {
	root := t.TempDir()
	write(t, root, "usr/lib/os-release", "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n")
	_ = os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	_ = os.Symlink("../usr/lib/os-release", filepath.Join(root, "etc/os-release"))
	write(t, root, "var/lib/dpkg/status", dpkgStatus)
	write(t, root, "usr/local/CyberCP/cyberpanel_version.py", "VERSION = '2.3'\nBUILD = 5\n")
	write(t, root, "usr/local/lsws/VERSION", "1.7.19\n")
	write(t, root, "usr/local/include/node/node_version.h", "#define NODE_MAJOR_VERSION 20\n#define NODE_MINOR_VERSION 11\n#define NODE_PATCH_VERSION 1\n")
	write(t, root, "app/package.json", `{"name":"shop","version":"0.4.0","dependencies":{"next":"^14.1.0","react":"18.2.0"}}`)
	write(t, root, "app/package-lock.json", `{"lockfileVersion":3,"packages":{"":{"name":"shop"},"node_modules/next":{"version":"14.1.0"},"node_modules/react":{"version":"18.2.0"},"node_modules/foo/node_modules/next":{"version":"13.0.0"}}}`)
	write(t, root, "home/example.com/public_html/wp-includes/version.php", "<?php\n$wp_version = '6.4.2';\n")
	_ = os.MkdirAll(filepath.Join(root, "usr/local/lib/python3.11/site-packages/Django-4.2.7.dist-info"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "usr/local/lib/python3.11/site-packages/requests-2.31.0.dist-info"), 0o755)
	// a Go binary: this test itself
	self, _ := os.Executable()
	b, _ := os.ReadFile(self)
	write(t, root, "usr/local/bin/tool", string(b))
	// a planted link: must not be followed out
	_ = os.Symlink("/etc/passwd", filepath.Join(root, "usr/local/go"))
	return root
}

func TestScanFindsSoftware(t *testing.T) {
	fs, err := OpenRoot(sampleRoot(t), "test")
	if err != nil {
		t.Skip(err)
	}
	defer fs.Close()
	tg := Scan(context.Background(), fs, Meta{Key: "host", Kind: "host", Name: "srv", WorkingDir: "/app", Env: map[string]string{"NGINX_VERSION": "1.25.3"}, Host: true})

	if tg.OS == nil || tg.OS.Ecosystem != "Debian:12" {
		t.Fatalf("os %+v", tg.OS)
	}
	apps := map[string]App{}
	for _, a := range tg.Apps {
		apps[a.Name] = a
	}
	for name, want := range map[string]string{
		"CyberPanel": "2.3.5", "OpenLiteSpeed": "1.7.19", "Node.js": "20.11.1", "Next.js": "14.1.0", "nginx": "1.22.1-9+deb12u1",
		"OpenSSL": "3.0.11-1~deb12u1", "WordPress (/home/example.com/public_html)": "6.4.2", "Django": "4.2.7", "shop": "0.4.0",
	} {
		if apps[name].Version != want {
			t.Errorf("%s = %q, want %q (apps %v)", name, apps[name].Version, want, tg.Apps)
		}
	}
	if tg.Apps[0].Kind != "panel" {
		t.Errorf("the panel should come first: %v", tg.Apps[0])
	}
	pk := map[string]Package{}
	for _, p := range tg.Packages {
		pk[p.Manager+":"+p.Name] = p
	}
	// advisories are by source package: libssl3 and openssl are one entry
	if p := pk["dpkg:openssl"]; p.Version != "3.0.11-1~deb12u1" || p.Ecosystem != "Debian:12" {
		t.Errorf("openssl %+v", p)
	}
	if _, ok := pk["dpkg:removed-thing"]; ok {
		t.Error("a removed package was listed")
	}
	have := map[string]bool{}
	for _, p := range tg.Packages {
		have[p.Manager+":"+p.Name+"@"+p.Version] = true
	}
	// both the app's next and the copy nested under foo are checked
	if !have["npm:next@14.1.0"] || !have["npm:next@13.0.0"] || pk["pip:requests"].Version != "2.31.0" || pk["pip:requests"].Ecosystem != "PyPI" {
		t.Errorf("language packages %v", have)
	}
	if p := pk["go:stdlib"]; p.Ecosystem != "Go" || p.Version == "" || p.Binary != "tool" {
		t.Errorf("Go build info %+v", p)
	}
	if _, ok := pk["go:golang.org/x/sys"]; !ok {
		t.Error("the Go binary's modules were not read")
	}
	for _, a := range tg.Apps {
		if a.Name == "Go" {
			t.Errorf("the planted /usr/local/go link was followed: %+v", a)
		}
	}
}

func TestEcosystems(t *testing.T) {
	for _, c := range [][4]string{
		{"debian", "12", "", "Debian:12"}, {"ubuntu", "22.04", "22.04.3 LTS (Jammy Jellyfish)", "Ubuntu:22.04:LTS"},
		{"ubuntu", "23.10", "23.10 (Mantic Minotaur)", "Ubuntu:23.10"}, {"alpine", "3.19.1", "", "Alpine:v3.19"}, {"rocky", "9.3", "", ""},
	} {
		if got := ecosystem(c[0], c[1], c[2]); got != c[3] {
			t.Errorf("%v: %q", c, got)
		}
	}
}

func TestApk(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/os-release", "ID=alpine\nVERSION_ID=3.19.1\n")
	write(t, root, "lib/apk/db/installed", "C:Q1x=\nP:musl\nV:1.2.4_git20230717-r4\no:musl\n\nP:libcrypto3\nV:3.1.4-r5\no:openssl\n\nP:nginx\nV:1.24.0-r15\no:nginx\n")
	fs, err := OpenRoot(root, "test")
	if err != nil {
		t.Skip(err)
	}
	defer fs.Close()
	tg := Scan(context.Background(), fs, Meta{Key: "docker:x"})
	got := map[string]string{}
	for _, p := range tg.Packages {
		got[p.Name] = p.Version + " " + p.Ecosystem
	}
	if got["openssl"] != "3.1.4-r5 Alpine:v3.19" || got["musl"] == "" {
		t.Errorf("apk %v", got)
	}
	if !hasApp(tg, "nginx") || !hasApp(tg, "musl") {
		t.Errorf("apps %v", tg.Apps)
	}
}

func TestCVSS3(t *testing.T) {
	for v, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N": 9.1,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
		"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N": 5.3,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N": 6.4,
	} {
		if got, ok := cvss3(v); !ok || got != want {
			t.Errorf("%s = %v, want %v", v, got, want)
		}
	}
	if _, ok := cvss3("CVSS:3.1/AV:X"); ok {
		t.Error("a broken vector scored")
	}
}

type memCache map[string][2]string

func (c memCache) GetVuln(id string) (string, string, bool) { v, ok := c[id]; return v[0], v[1], ok }
func (c memCache) PutVuln(id, mod, data string) error       { c[id] = [2]string{data, mod}; return nil }

func TestOSVCheck(t *testing.T) {
	fetched := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			var q struct{ Queries []osvQuery }
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &q)
			var res []map[string]any
			for _, x := range q.Queries {
				if x.Package.Name == "next" {
					res = append(res, map[string]any{"vulns": []map[string]string{{"id": "GHSA-f82v-jwr5-mffw", "modified": "2025-04-01"}}})
				} else {
					res = append(res, map[string]any{})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": res})
		case "/v1/vulns/GHSA-f82v-jwr5-mffw":
			fetched++
			_, _ = io.WriteString(w, `{"id":"GHSA-f82v-jwr5-mffw","summary":"Authorization Bypass in Next.js Middleware","aliases":["CVE-2025-29927"],
			  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}],
			  "affected":[{"package":{"name":"next","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"13.0.0"},{"fixed":"13.5.9"}]}]},
			    {"package":{"name":"next","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"14.0.0"},{"fixed":"14.2.25"}]}]},
			    {"package":{"name":"next","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"15.0.0"},{"fixed":"15.2.3"}]}]}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cache := memCache{}
	o := &OSV{API: srv.URL, Cache: cache}
	pkgs := []Package{{Name: "next", Version: "14.1.0", Ecosystem: "npm"}, {Name: "react", Version: "18.2.0", Ecosystem: "npm"}, {Name: "x", Version: "1", Ecosystem: ""}}
	res, err := o.Check(context.Background(), pkgs)
	if err != nil {
		t.Fatal(err)
	}
	f := res[pkgKey{"npm", "next", "14.1.0"}]
	if len(f) != 1 || f[0].Severity != "critical" || f[0].Score != 9.1 || f[0].Fixed != "14.2.25" || f[0].CVEs[0] != "CVE-2025-29927" {
		t.Fatalf("finding %+v", f)
	}
	if len(res[pkgKey{"npm", "react", "18.2.0"}]) != 0 {
		t.Error("react has no finding")
	}
	// the second check uses the cache
	if _, err := o.Check(context.Background(), pkgs); err != nil || fetched != 1 {
		t.Errorf("advisory fetched %d times: %v", fetched, err)
	}
}

func TestCleanStripsControlCharacters(t *testing.T) {
	if got := clean("ok\x1b[31m\nname<script>" + strings.Repeat("x", 400)); strings.ContainsAny(got, "\x1b\n") || len(got) > maxText {
		t.Errorf("%q", got)
	}
}
