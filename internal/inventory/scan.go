package inventory

import (
	"bufio"
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Meta is what the container engine already knows about a target.
type Meta struct {
	Key, Kind, Name, Image string
	Running                bool
	WorkingDir             string
	Command                []string          // entrypoint, then cmd
	Env                    map[string]string // only the *_VERSION ones are used
	Labels                 map[string]string
	Host                   bool // the server itself: look in its usual places for binaries
}

// Size limits for the files that are read.
const (
	limitSmall  = 1 << 20   // os-release, package.json, version files
	limitDB     = 32 << 20  // package databases and lockfiles
	limitBinary = 160 << 20 // binaries read for Go build info (random access, not loaded)
	maxBinaries = 30
	maxDirNames = 2000
)

// Scan reads one target's software. It returns what it found by the time
// ctx ends.
func Scan(ctx context.Context, fs FS, m Meta) *Target {
	t := &Target{Key: m.Key, Kind: m.Kind, Name: clean(m.Name), Image: clean(m.Image), Running: m.Running, Via: fs.Via(),
		Apps: []App{}, Packages: []Package{}, Findings: []Finding{}}
	start := time.Now()
	steps := []func(){
		func() { t.OS = readOS(fs, t) },
		func() { readDpkg(fs, t) },
		func() { readApk(fs, t) },
		func() { fromImage(m, t) },
		func() { knownFiles(fs, t) },
		func() { nodeApps(fs, m, t) },
		func() { pythonPackages(fs, t) },
		func() { goBinaries(ctx, fs, m, t) },
		func() { wordpress(fs, t) },
	}
	for _, step := range steps {
		if ctx.Err() != nil {
			t.Error = "the scan ran out of time; what was found so far is shown"
			break
		}
		step()
	}
	sort.SliceStable(t.Apps, func(i, j int) bool { return appRank(t.Apps[i].Kind) < appRank(t.Apps[j].Kind) })
	t.ScannedAt, t.TookMS = time.Now().UTC(), time.Since(start).Milliseconds()
	return t
}

func appRank(kind string) int {
	switch kind {
	case "panel":
		return 0
	case "server":
		return 1
	case "framework":
		return 2
	case "runtime":
		return 3
	case "app":
		return 4
	}
	return 5
}

// odd reports a well-known file that is there but is not a regular file
// (a link out of the container, a device, a FIFO): it was not read, and
// the operator may want to know someone planted it.
func odd(t *Target, p string, err error) {
	if err == nil || IsNotExist(err) {
		return
	}
	switch {
	case errors.Is(err, ErrNotRegular):
		t.note(p + " is not a regular file and was not read")
	case errors.Is(err, ErrTooLarge):
		t.note(p + " is larger than SkyGuard reads and was skipped")
	case errors.Is(err, ErrUnsupported):
	default:
		t.note(fmt.Sprintf("%s could not be read: %v", p, err))
	}
}

// ── the distribution ────────────────────────────────────────────────────────

func readOS(fs FS, t *Target) *OSInfo {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		b, err := fs.ReadFile(p, limitSmall)
		if err != nil {
			odd(t, p, err)
			continue
		}
		kv := parseKV(b)
		o := &OSInfo{ID: clean(kv["ID"]), VersionID: clean(kv["VERSION_ID"]), Name: clean(kv["PRETTY_NAME"])}
		o.Ecosystem = ecosystem(o.ID, o.VersionID, kv["VERSION"])
		if o.Ecosystem == "" && o.ID != "" {
			t.note(fmt.Sprintf("OSV.dev has no advisories for %s %s packages, so they are listed but not checked", o.ID, o.VersionID))
		}
		return o
	}
	return nil
}

func parseKV(b []byte) map[string]string {
	kv := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		kv[k] = strings.Trim(v, `"'`)
	}
	return kv
}

// ecosystem is OSV's name for a distribution's packages.
func ecosystem(id, version, full string) string {
	switch id {
	case "debian":
		if major, _, _ := strings.Cut(version, "."); major != "" {
			return "Debian:" + major
		}
	case "ubuntu":
		if version != "" {
			if strings.Contains(full, "LTS") {
				return "Ubuntu:" + version + ":LTS"
			}
			return "Ubuntu:" + version
		}
	case "alpine":
		parts := strings.Split(version, ".")
		if len(parts) >= 2 {
			return "Alpine:v" + parts[0] + "." + parts[1]
		}
	}
	return ""
}

// ── OS packages ─────────────────────────────────────────────────────────────

// notable maps OS package names to the software people know them as.
var notable = []struct {
	re         *regexp.Regexp
	name, kind string
}{
	{regexp.MustCompile(`^nginx(-full|-core|-light|-extras)?$`), "nginx", "server"},
	{regexp.MustCompile(`^(apache2|httpd)$`), "Apache httpd", "server"},
	{regexp.MustCompile(`^openlitespeed$`), "OpenLiteSpeed", "server"},
	{regexp.MustCompile(`^(openssh-server|openssh)$`), "OpenSSH", "server"},
	{regexp.MustCompile(`^(mysql-server|mysql-server-core-[0-9.]+|mysql-community-server)$`), "MySQL", "server"},
	{regexp.MustCompile(`^(mariadb-server|mariadb-server-core|mariadb-server-[0-9.]+)$`), "MariaDB", "server"},
	{regexp.MustCompile(`^postgresql-[0-9]+$|^postgresql[0-9]*$`), "PostgreSQL", "server"},
	{regexp.MustCompile(`^(redis-server|redis)$`), "Redis", "server"},
	{regexp.MustCompile(`^(memcached)$`), "Memcached", "server"},
	{regexp.MustCompile(`^(mongodb-org-server|mongodb-server)$`), "MongoDB", "server"},
	{regexp.MustCompile(`^haproxy$`), "HAProxy", "server"},
	{regexp.MustCompile(`^(bind9|bind)$`), "BIND", "server"},
	{regexp.MustCompile(`^(postfix)$`), "Postfix", "server"},
	{regexp.MustCompile(`^exim4-daemon-(light|heavy)$|^exim$`), "Exim", "server"},
	{regexp.MustCompile(`^(dovecot-core|dovecot)$`), "Dovecot", "server"},
	{regexp.MustCompile(`^(proftpd-core|proftpd-basic|proftpd)$`), "ProFTPD", "server"},
	{regexp.MustCompile(`^pure-ftpd(-common)?$`), "Pure-FTPd", "server"},
	{regexp.MustCompile(`^vsftpd$`), "vsftpd", "server"},
	{regexp.MustCompile(`^(docker-ce|docker\.io|moby-engine)$`), "Docker Engine", "server"},
	{regexp.MustCompile(`^(containerd\.io|containerd)$`), "containerd", "server"},
	{regexp.MustCompile(`^incus$`), "Incus", "server"},
	{regexp.MustCompile(`^php[0-9.]*-fpm$|^php[0-9.]*$|^php[0-9]+-cli$`), "PHP", "runtime"},
	{regexp.MustCompile(`^nodejs$`), "Node.js", "runtime"},
	{regexp.MustCompile(`^python3\.[0-9]+$|^python3$`), "Python", "runtime"},
	{regexp.MustCompile(`^openjdk-[0-9]+-jre(-headless)?$|^openjdk[0-9]*$`), "OpenJDK", "runtime"},
	{regexp.MustCompile(`^(openssl|libssl3|libssl3t64)$`), "OpenSSL", "library"},
	{regexp.MustCompile(`^(libc6|glibc)$`), "glibc", "library"},
	{regexp.MustCompile(`^musl$`), "musl", "library"},
	{regexp.MustCompile(`^sudo$`), "sudo", "library"},
}

func notablePackage(t *Target, name, version, manager string) {
	for _, n := range notable {
		if n.re.MatchString(name) {
			t.addApp(App{Name: n.name, Version: version, Kind: n.kind, Where: manager + " package " + name})
			return
		}
	}
}

func readDpkg(fs FS, t *Target) {
	var blobs [][]byte
	if b, err := fs.ReadFile("/var/lib/dpkg/status", limitDB); err == nil {
		blobs = append(blobs, b)
	} else {
		odd(t, "/var/lib/dpkg/status", err)
	}
	// distroless images keep one file per package
	if names, err := fs.ReadDir("/var/lib/dpkg/status.d", maxDirNames); err == nil {
		for _, n := range names {
			if strings.HasSuffix(n, ".md5sums") {
				continue
			}
			if b, err := fs.ReadFile(path.Join("/var/lib/dpkg/status.d", n), limitSmall); err == nil {
				blobs = append(blobs, b)
			}
		}
	}
	eco := ""
	if t.OS != nil {
		eco = t.OS.Ecosystem
	}
	seen := map[string]bool{}
	for _, b := range blobs {
		for _, p := range bytes.Split(b, []byte("\n\n")) {
			kv := map[string]string{}
			sc := bufio.NewScanner(bytes.NewReader(p))
			sc.Buffer(make([]byte, 64<<10), 1<<20)
			for sc.Scan() {
				l := sc.Text()
				if l == "" || l[0] == ' ' || l[0] == '\t' {
					continue
				}
				if k, v, ok := strings.Cut(l, ":"); ok {
					kv[k] = strings.TrimSpace(v)
				}
			}
			name, version := kv["Package"], kv["Version"]
			if name == "" || version == "" || (kv["Status"] != "" && !strings.HasSuffix(kv["Status"], " installed")) {
				continue
			}
			notablePackage(t, name, version, "dpkg")
			// advisories name the source package, at the source version
			src, srcVersion := name, version
			if s := kv["Source"]; s != "" {
				src = s
				if n, v, ok := strings.Cut(s, " ("); ok {
					src, srcVersion = n, strings.TrimSuffix(v, ")")
				}
			}
			if k := src + "@" + srcVersion; !seen[k] {
				seen[k] = true
				t.addPackage(Package{Name: src, Version: srcVersion, Ecosystem: eco, Manager: "dpkg", Binary: name})
			}
		}
	}
}

func readApk(fs FS, t *Target) {
	b, err := fs.ReadFile("/lib/apk/db/installed", limitDB)
	if err != nil {
		odd(t, "/lib/apk/db/installed", err)
		return
	}
	eco := ""
	if t.OS != nil {
		eco = t.OS.Ecosystem
	}
	seen := map[string]bool{}
	for _, rec := range bytes.Split(b, []byte("\n\n")) {
		var name, version, origin string
		for _, l := range strings.Split(string(rec), "\n") {
			if len(l) < 2 || l[1] != ':' {
				continue
			}
			switch l[0] {
			case 'P':
				name = l[2:]
			case 'V':
				version = l[2:]
			case 'o':
				origin = l[2:]
			}
		}
		if name == "" || version == "" {
			continue
		}
		notablePackage(t, name, version, "apk")
		if origin == "" {
			origin = name
		}
		if k := origin + "@" + version; !seen[k] {
			seen[k] = true
			t.addPackage(Package{Name: origin, Version: version, Ecosystem: eco, Manager: "apk", Binary: name})
		}
	}
}

// ── what the image says about itself ────────────────────────────────────────

var envApps = map[string][2]string{
	"NGINX_VERSION": {"nginx", "server"}, "HTTPD_VERSION": {"Apache httpd", "server"}, "CADDY_VERSION": {"Caddy", "server"},
	"NODE_VERSION": {"Node.js", "runtime"}, "GOLANG_VERSION": {"Go", "runtime"}, "PYTHON_VERSION": {"Python", "runtime"},
	"PHP_VERSION": {"PHP", "runtime"}, "JAVA_VERSION": {"Java", "runtime"}, "RUBY_VERSION": {"Ruby", "runtime"},
	"REDIS_VERSION": {"Redis", "server"}, "MONGO_VERSION": {"MongoDB", "server"}, "MYSQL_VERSION": {"MySQL", "server"},
	"MARIADB_VERSION": {"MariaDB", "server"}, "PG_VERSION": {"PostgreSQL", "server"}, "RABBITMQ_VERSION": {"RabbitMQ", "server"},
	"ELASTIC_VERSION": {"Elasticsearch", "server"}, "TOMCAT_VERSION": {"Tomcat", "server"}, "WORDPRESS_VERSION": {"WordPress", "app"},
	"GHOST_VERSION": {"Ghost", "app"}, "NEXTCLOUD_VERSION": {"Nextcloud", "app"}, "GITEA_VERSION": {"Gitea", "app"},
}

func fromImage(m Meta, t *Target) {
	keys := make([]string, 0, len(m.Env))
	for k := range m.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if a, ok := envApps[k]; ok {
			t.addApp(App{Name: a[0], Version: m.Env[k], Kind: a[1], Where: "image environment " + k})
		}
	}
	if v := m.Labels["org.opencontainers.image.version"]; v != "" {
		name := m.Labels["org.opencontainers.image.title"]
		if name == "" {
			name = m.Image
		}
		t.addApp(App{Name: name, Version: v, Kind: "image", Where: "image label org.opencontainers.image.version"})
	}
}

// ── software that records its version in a file ─────────────────────────────

var (
	reDefine     = regexp.MustCompile(`#define\s+(\w+)\s+"?([^"\s]+)"?`)
	reCyberPanel = regexp.MustCompile(`(?m)^(VERSION|BUILD)\s*=\s*['"]?([0-9.]+)`)
	reJavaRel    = regexp.MustCompile(`(?m)^JAVA_VERSION="([^"]+)"`)
	reNginxBin   = regexp.MustCompile(`(nginx|openresty)/([0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)`)
	reWordPress  = regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`)
)

func knownFiles(fs FS, t *Target) {
	// CyberPanel: cyberpanel_version.py (newer) or version.txt
	if b, err := fs.ReadFile("/usr/local/CyberCP/cyberpanel_version.py", limitSmall); err == nil {
		v := map[string]string{}
		for _, m := range reCyberPanel.FindAllStringSubmatch(string(b), -1) {
			v[m[1]] = m[2]
		}
		if v["VERSION"] != "" {
			t.addApp(App{Name: "CyberPanel", Version: strings.TrimSuffix(v["VERSION"]+"."+v["BUILD"], "."), Kind: "panel", Where: "/usr/local/CyberCP/cyberpanel_version.py"})
		}
	} else if b, err := fs.ReadFile("/usr/local/CyberCP/version.txt", limitSmall); err == nil {
		var v struct {
			Version string `json:"version"`
			Build   any    `json:"build"`
		}
		if json.Unmarshal(b, &v) == nil && v.Version != "" {
			t.addApp(App{Name: "CyberPanel", Version: fmt.Sprintf("%s.%v", v.Version, v.Build), Kind: "panel", Where: "/usr/local/CyberCP/version.txt"})
		}
	}
	if b, err := fs.ReadFile("/usr/local/lsws/VERSION", limitSmall); err == nil {
		t.addApp(App{Name: "OpenLiteSpeed", Version: firstLine(b), Kind: "server", Where: "/usr/local/lsws/VERSION"})
	}
	// Node.js, from its header (official images build it from source)
	for _, p := range []string{"/usr/local/include/node/node_version.h", "/usr/include/node/node_version.h"} {
		if b, err := fs.ReadFile(p, limitSmall); err == nil {
			d := defines(b)
			if d["NODE_MAJOR_VERSION"] != "" {
				t.addApp(App{Name: "Node.js", Version: d["NODE_MAJOR_VERSION"] + "." + d["NODE_MINOR_VERSION"] + "." + d["NODE_PATCH_VERSION"], Kind: "runtime", Where: p})
				break
			}
		}
	}
	if b, err := fs.ReadFile("/usr/local/go/VERSION", limitSmall); err == nil {
		v := strings.TrimPrefix(firstLine(b), "go")
		t.addApp(App{Name: "Go", Version: v, Kind: "runtime", Where: "/usr/local/go/VERSION"})
		t.addPackage(Package{Name: "stdlib", Version: v, Ecosystem: "Go", Manager: "go"})
	}
	if b, err := fs.ReadFile("/usr/local/include/php/main/php_version.h", limitSmall); err == nil {
		if v := defines(b)["PHP_VERSION"]; v != "" {
			t.addApp(App{Name: "PHP", Version: v, Kind: "runtime", Where: "/usr/local/include/php/main/php_version.h"})
		}
	}
	for _, base := range []string{"/usr/local/include", "/usr/include"} {
		names, _ := fs.ReadDir(base, maxDirNames)
		for _, n := range names {
			if strings.HasPrefix(n, "python3") {
				p := path.Join(base, n, "patchlevel.h")
				if b, err := fs.ReadFile(p, limitSmall); err == nil {
					if v := defines(b)["PY_VERSION"]; v != "" {
						t.addApp(App{Name: "Python", Version: v, Kind: "runtime", Where: p})
					}
				}
			}
		}
	}
	javaHomes := []string{"/opt/java/openjdk"}
	if names, err := fs.ReadDir("/usr/lib/jvm", 50); err == nil {
		for _, n := range names {
			javaHomes = append(javaHomes, "/usr/lib/jvm/"+n)
		}
	}
	for _, h := range javaHomes {
		if b, err := fs.ReadFile(h+"/release", limitSmall); err == nil {
			if m := reJavaRel.FindSubmatch(b); m != nil {
				t.addApp(App{Name: "Java", Version: string(m[1]), Kind: "runtime", Where: h + "/release"})
				break
			}
		}
	}
	// nginx built from source (or OpenResty) records its version in the binary
	if !hasApp(t, "nginx") {
		for _, p := range []string{"/usr/sbin/nginx", "/usr/local/nginx/sbin/nginx", "/usr/local/openresty/nginx/sbin/nginx"} {
			if b, err := fs.ReadFile(p, limitDB); err == nil {
				if m := reNginxBin.FindSubmatch(b); m != nil {
					name := "nginx"
					if string(m[1]) == "openresty" {
						name = "OpenResty"
					}
					t.addApp(App{Name: name, Version: string(m[2]), Kind: "server", Where: p})
					break
				}
			}
		}
	}
}

func hasApp(t *Target, name string) bool {
	for _, a := range t.Apps {
		if strings.EqualFold(a.Name, name) {
			return true
		}
	}
	return false
}

func defines(b []byte) map[string]string {
	out := map[string]string{}
	for _, m := range reDefine.FindAllSubmatch(b, -1) {
		out[string(m[1])] = string(m[2])
	}
	return out
}

func firstLine(b []byte) string {
	l, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	return strings.TrimSpace(l)
}

// ── Node.js applications ────────────────────────────────────────────────────

var frameworks = map[string]string{
	"next": "Next.js", "nuxt": "Nuxt", "express": "Express", "@nestjs/core": "NestJS", "fastify": "Fastify",
	"koa": "Koa", "@sveltejs/kit": "SvelteKit", "astro": "Astro", "@remix-run/node": "Remix", "@strapi/strapi": "Strapi",
	"gatsby": "Gatsby", "react": "React", "vue": "Vue", "@angular/core": "Angular",
}

func nodeApps(fs FS, m Meta, t *Target) {
	dirs := []string{}
	seen := map[string]bool{}
	for _, d := range []string{m.WorkingDir, "/app", "/usr/src/app", "/opt/app", "/srv/app", "/var/www/app", "/home/node/app", "/workspace"} {
		if d = path.Clean("/" + d); d != "/" && !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	for _, dir := range dirs {
		b, err := fs.ReadFile(dir+"/package.json", limitSmall)
		if err != nil {
			continue
		}
		var pj struct {
			Name            string            `json:"name"`
			Version         string            `json:"version"`
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if json.Unmarshal(b, &pj) != nil {
			continue
		}
		name := pj.Name
		if name == "" {
			name = path.Base(dir)
		}
		t.addApp(App{Name: name, Version: pj.Version, Kind: "app", Where: dir + "/package.json"})
		locked := lockedVersions(fs, dir, t)
		for dep, label := range frameworks {
			want, direct := pj.Dependencies[dep]
			if !direct {
				if _, dev := pj.DevDependencies[dep]; !dev {
					continue
				}
			}
			v := locked[dep]
			if v == "" {
				if b, err := fs.ReadFile(dir+"/node_modules/"+dep+"/package.json", limitSmall); err == nil {
					var p struct{ Version string }
					_ = json.Unmarshal(b, &p)
					v = p.Version
				}
			}
			where := dir + "/package-lock.json"
			if v == "" {
				v, where = want, dir+"/package.json (range, not the installed version)"
			}
			t.addApp(App{Name: label, Version: v, Kind: "framework", Where: where})
		}
	}
}

// lockedVersions reads the exact versions from a lockfile and adds every
// locked package for the vulnerability check.
func lockedVersions(fs FS, dir string, t *Target) map[string]string {
	out := map[string]string{}
	add := func(name, version string) {
		if name == "" || version == "" {
			return
		}
		if _, ok := out[name]; !ok {
			out[name] = version
		}
		t.addPackage(Package{Name: name, Version: version, Ecosystem: "npm", Manager: "npm"})
	}
	if b, err := fs.ReadFile(dir+"/package-lock.json", limitDB); err == nil {
		var lock struct {
			Packages     map[string]struct{ Version string } `json:"packages"`
			Dependencies map[string]json.RawMessage          `json:"dependencies"`
		}
		if json.Unmarshal(b, &lock) == nil {
			if len(lock.Packages) > 0 {
				keys := make([]string, 0, len(lock.Packages))
				for k := range lock.Packages {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				// the installed version is the top-level one; nested copies are
				// checked too but do not name it
				for _, k := range keys {
					if strings.HasPrefix(k, "node_modules/") && !strings.Contains(k[len("node_modules/"):], "node_modules/") {
						add(k[len("node_modules/"):], lock.Packages[k].Version)
					}
				}
				for _, k := range keys {
					if i := strings.LastIndex(k, "node_modules/"); i > 0 {
						t.addPackage(Package{Name: k[i+len("node_modules/"):], Version: lock.Packages[k].Version, Ecosystem: "npm", Manager: "npm"})
					}
				}
			} else {
				walkLockV1(lock.Dependencies, add, 0)
			}
			return out
		}
	}
	if b, err := fs.ReadFile(dir+"/yarn.lock", limitDB); err == nil {
		var names []string
		for _, l := range strings.Split(string(b), "\n") {
			switch {
			case l != "" && l[0] != ' ' && l[0] != '#' && strings.HasSuffix(l, ":"):
				names = names[:0]
				for _, spec := range strings.Split(strings.TrimSuffix(l, ":"), ",") {
					spec = strings.Trim(strings.TrimSpace(spec), `"`)
					if i := strings.LastIndex(spec, "@"); i > 0 {
						names = append(names, spec[:i])
					}
				}
			case strings.HasPrefix(l, "  version "):
				v := strings.Trim(strings.TrimPrefix(l, "  version "), `"`)
				for _, n := range names {
					add(n, v)
				}
			}
		}
		return out
	}
	if b, err := fs.ReadFile(dir+"/pnpm-lock.yaml", limitDB); err == nil {
		re := regexp.MustCompile(`(?m)^  '?/?((?:@[^@/\s]+/)?[^@/\s']+)@([0-9][^:(\s']*)`)
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			add(m[1], m[2])
		}
	}
	return out
}

func walkLockV1(deps map[string]json.RawMessage, add func(string, string), depth int) {
	if depth > 20 {
		return
	}
	for name, raw := range deps {
		var d struct {
			Version      string                     `json:"version"`
			Dependencies map[string]json.RawMessage `json:"dependencies"`
		}
		if json.Unmarshal(raw, &d) == nil {
			add(name, d.Version)
			walkLockV1(d.Dependencies, add, depth+1)
		}
	}
}

// ── Python packages ─────────────────────────────────────────────────────────

var pyApps = map[string]string{"django": "Django", "flask": "Flask", "fastapi": "FastAPI"}

func pythonPackages(fs FS, t *Target) {
	var dirs []string
	for _, base := range []string{"/usr/lib", "/usr/local/lib", "/usr/local/CyberPanel/lib", "/opt/venv/lib", "/app/.venv/lib"} {
		names, _ := fs.ReadDir(base, maxDirNames)
		for _, n := range names {
			if strings.HasPrefix(n, "python3") {
				dirs = append(dirs, path.Join(base, n, "site-packages"), path.Join(base, n, "dist-packages"))
			}
		}
	}
	dirs = append(dirs, "/usr/lib/python3/dist-packages")
	seen := map[string]bool{}
	for _, d := range dirs {
		names, err := fs.ReadDir(d, maxDirNames)
		if err != nil {
			continue
		}
		for _, n := range names {
			meta := strings.TrimSuffix(strings.TrimSuffix(n, ".dist-info"), ".egg-info")
			if meta == n {
				continue
			}
			i := strings.LastIndex(meta, "-")
			if i <= 0 {
				continue
			}
			name := strings.ToLower(strings.ReplaceAll(meta[:i], "_", "-"))
			version := meta[i+1:]
			if k := name + "@" + version; !seen[k] {
				seen[k] = true
				t.addPackage(Package{Name: name, Version: version, Ecosystem: "PyPI", Manager: "pip"})
				if label, ok := pyApps[name]; ok {
					t.addApp(App{Name: label, Version: version, Kind: "framework", Where: d})
				}
			}
		}
	}
}

// ── Go binaries ─────────────────────────────────────────────────────────────

var pathDirs = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

func goBinaries(ctx context.Context, fs FS, m Meta, t *Target) {
	var cands []string
	seen := map[string]bool{}
	add := func(p string) {
		if p = path.Clean(p); !seen[p] && len(cands) < maxBinaries {
			seen[p] = true
			cands = append(cands, p)
		}
	}
	if len(m.Command) > 0 {
		c := m.Command[0]
		if strings.HasPrefix(c, "/") {
			add(c)
		} else if !strings.Contains(c, "/") {
			for _, d := range append([]string{m.WorkingDir}, pathDirs...) {
				if d != "" {
					add(path.Join(d, c))
				}
			}
		} else if m.WorkingDir != "" {
			add(path.Join(m.WorkingDir, c))
		}
	}
	dirs := []string{"/usr/local/bin", "/app", m.WorkingDir}
	if m.Host {
		dirs = append(dirs, "/usr/local/sbin")
		if names, err := fs.ReadDir("/opt", 100); err == nil {
			for _, n := range names {
				dirs = append(dirs, "/opt/"+n, "/opt/"+n+"/bin")
			}
		}
	}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		names, _ := fs.ReadDir(d, 200)
		sort.Strings(names)
		for _, n := range names {
			add(path.Join(d, n))
		}
	}
	for _, p := range cands {
		if ctx.Err() != nil {
			return
		}
		readGoBinary(fs, p, t)
	}
}

func readGoBinary(fs FS, p string, t *Target) {
	f, err := fs.OpenFile(p, limitBinary)
	if err != nil {
		return
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := f.ReadAt(magic, 0); err != nil || string(magic) != "\x7fELF" {
		return
	}
	var bi *buildinfo.BuildInfo
	func() {
		defer func() { _ = recover() }() // a crafted ELF must not take SkyGuard down
		bi, err = buildinfo.Read(f)
	}()
	if bi == nil || err != nil {
		return
	}
	goVersion := strings.TrimPrefix(strings.Fields(bi.GoVersion + " ")[0], "go")
	name, version := path.Base(p), bi.Main.Version
	if bi.Main.Path != "" {
		name = bi.Main.Path
	}
	t.addApp(App{Name: name, Version: version, Kind: "app", Where: p + " · built with Go " + goVersion})
	t.addPackage(Package{Name: "stdlib", Version: goVersion, Ecosystem: "Go", Manager: "go", Binary: path.Base(p)})
	for _, d := range bi.Deps {
		if d.Replace != nil {
			d = d.Replace
		}
		if d.Version != "" && d.Version != "(devel)" {
			t.addPackage(Package{Name: d.Path, Version: strings.TrimPrefix(d.Version, "v"), Ecosystem: "Go", Manager: "go", Binary: path.Base(p)})
		}
	}
}

// ── WordPress sites ─────────────────────────────────────────────────────────

func wordpress(fs FS, t *Target) {
	var roots []string
	add := func(p string) {
		if len(roots) < 60 {
			roots = append(roots, p)
		}
	}
	add("/var/www/html")
	add("/usr/share/nginx/html")
	for _, base := range []string{"/var/www", "/srv/www"} {
		names, _ := fs.ReadDir(base, 200)
		for _, n := range names {
			add(path.Join(base, n))
			add(path.Join(base, n, "public_html"))
		}
	}
	// CyberPanel keeps each site in /home/<domain>/public_html
	names, _ := fs.ReadDir("/home", 500)
	for _, n := range names {
		add(path.Join("/home", n, "public_html"))
	}
	for _, r := range roots {
		b, err := fs.ReadFile(r+"/wp-includes/version.php", limitSmall)
		if err != nil {
			continue
		}
		if m := reWordPress.FindSubmatch(b); m != nil {
			t.addApp(App{Name: "WordPress (" + r + ")", Version: string(m[1]), Kind: "app", Where: r + "/wp-includes/version.php"})
		}
	}
}
