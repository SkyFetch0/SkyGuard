package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// Release is one published release and the files this machine needs.
type Release struct {
	Tag        string    `json:"tag"`
	Version    string    `json:"version"`
	Name       string    `json:"name"`
	Notes      string    `json:"notes"`
	URL        string    `json:"url"` // the release page
	Published  time.Time `json:"published"`
	Prerelease bool      `json:"prerelease"`

	Binary    string `json:"-"` // download URL of skyguard-linux-<arch>
	Sums      string `json:"-"` // SHA256SUMS
	Signature string `json:"-"` // SHA256SUMS.sig, "" when unsigned
	Asset     string `json:"asset"`
	Signed    bool   `json:"signed"`
}

// AssetName is the binary a release publishes for this machine.
func AssetName() string { return "skyguard-" + runtime.GOOS + "-" + runtime.GOARCH }

// GitHub reads releases from the GitHub REST API.
type GitHub struct {
	API   string // https://api.github.com
	Repo  string // owner/name
	Token string
	HTTP  *http.Client
}

type ghRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	HTMLURL     string    `json:"html_url"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// Newest returns the highest release version the channel allows ("stable"
// skips pre-releases), or nil when the repository has none yet.
func (g *GitHub) Newest(ctx context.Context, channel string) (*Release, error) {
	var list []ghRelease
	if err := g.get(ctx, fmt.Sprintf("%s/repos/%s/releases?per_page=20", strings.TrimRight(g.API, "/"), g.Repo), &list); err != nil {
		return nil, err
	}
	var best *Release
	for _, r := range list {
		if r.Draft || (r.Prerelease && channel != "prerelease") || !IsRelease(r.TagName) {
			continue
		}
		rel := &Release{Tag: r.TagName, Version: strings.TrimPrefix(r.TagName, "v"), Name: r.Name, Notes: r.Body,
			URL: r.HTMLURL, Published: r.PublishedAt, Prerelease: r.Prerelease, Asset: AssetName()}
		if len(rel.Notes) > 20000 {
			rel.Notes = rel.Notes[:20000] + "\n…"
		}
		for _, a := range r.Assets {
			switch a.Name {
			case rel.Asset:
				rel.Binary = a.URL
			case "SHA256SUMS":
				rel.Sums = a.URL
			case "SHA256SUMS.sig":
				rel.Signature, rel.Signed = a.URL, true
			}
		}
		if best == nil || Compare(rel.Version, best.Version) > 0 {
			best = rel
		}
	}
	return best, nil
}

func (g *GitHub) get(ctx context.Context, url string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "skyguard-updater")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	resp, err := g.client().Do(req)
	if err != nil {
		return fmt.Errorf("asking GitHub: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("GitHub has no repository %s (or it is private: set update.github_token)", g.Repo)
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
		return errors.New("GitHub refused the request (its hourly limit for this address, or a bad token); it is tried again later")
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("GitHub answered %s", resp.Status)
	}
	return json.Unmarshal(body, into)
}

func (g *GitHub) client() *http.Client {
	if g.HTTP != nil {
		return g.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// download fetches url into memory, up to max bytes.
func download(ctx context.Context, c *http.Client, url, token string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "skyguard-updater")
	req.Header.Set("Accept", "application/octet-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is larger than %d MB", url, max>>20)
	}
	return b, nil
}
