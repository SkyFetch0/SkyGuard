package honeypot

import (
	"bufio"
	"fmt"
	"html"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/skyguard/skyguard/internal/config"
)

// HTTPHoneypot simulates a generic web server. It logs every request, serves
// believable login pages and captures credentials submitted to them (form
// posts and HTTP Basic Auth).
type HTTPHoneypot struct {
	cfg         config.HoneypotService
	eventLogger *EventLogger
	logger      *slog.Logger
	server      string // value of the Server: header
}

const (
	httpMaxRequest = 64 << 10 // request line + headers + body
	httpMaxBody    = 16 << 10
)

// NewHTTPHoneypot creates an HTTPHoneypot. The Server header comes from
// server_header (falling back to banner for older configs).
func NewHTTPHoneypot(cfg config.HoneypotService, eventLogger *EventLogger, logger *slog.Logger) *HTTPHoneypot {
	server := cfg.ServerHeader
	if server == "" {
		server = cfg.Banner
	}
	if server == "" {
		server = "Apache/2.4.41 (Ubuntu)"
	}
	return &HTTPHoneypot{cfg: cfg, eventLogger: eventLogger, logger: logger, server: server}
}

// Type implements Handler.
func (h *HTTPHoneypot) Type() string { return "http" }

// Handle reads one HTTP request, logs it, captures credentials and answers
// with a page matching the requested path.
func (h *HTTPHoneypot) Handle(conn net.Conn, sess Session) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	br := bufio.NewReader(io.LimitReader(conn, httpMaxRequest))
	req, err := http.ReadRequest(br)
	if err != nil {
		h.eventLogger.LogConnection(sess, "http", "malformed request: "+err.Error())
		h.writeResponse(conn, http.StatusBadRequest, "text/html", errorPage(400, "Bad Request", h.server))
		return nil
	}
	defer req.Body.Close()

	path := req.URL.RequestURI()
	data := fmt.Sprintf("method=%s path=%s host=%q ua=%q", req.Method, path, req.Host, req.UserAgent())
	h.logger.Info("http request", "source_ip", sess.IP, "method", req.Method, "path", path)
	h.eventLogger.LogConnection(sess, "http", data)

	if user, pass, ok := req.BasicAuth(); ok {
		h.eventLogger.LogCredential(sess, user, pass, "http-basic")
	}
	if req.Method == http.MethodPost {
		if user, pass, ok := formCredentials(req); ok {
			h.logger.Info("http credential attempt", "source_ip", sess.IP, "user", user, "path", path)
			h.eventLogger.LogCredential(sess, user, pass, "http")
		}
	}

	status, body := h.route(strings.ToLower(req.URL.Path), req.Method == http.MethodPost)
	h.writeResponse(conn, status, "text/html; charset=UTF-8", body)
	return nil
}

// credentialFields maps common login form field names (WordPress,
// phpMyAdmin, generic) to user / password pairs.
var credentialFields = [][2]string{
	{"log", "pwd"},
	{"pma_username", "pma_password"},
	{"username", "password"},
	{"user", "pass"},
	{"email", "password"},
	{"login", "password"},
}

func formCredentials(req *http.Request) (string, string, bool) {
	ct, _, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if ct != "application/x-www-form-urlencoded" {
		return "", "", false
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, httpMaxBody))
	if err != nil {
		return "", "", false
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return "", "", false
	}
	for _, f := range credentialFields {
		if form.Has(f[0]) || form.Has(f[1]) {
			return form.Get(f[0]), form.Get(f[1]), true
		}
	}
	return "", "", false
}

func (h *HTTPHoneypot) route(path string, failedLogin bool) (int, string) {
	switch {
	case path == "/wp-login.php" || path == "/wp-admin" || strings.HasPrefix(path, "/wp-admin/") || path == "/admin" || path == "/admin/":
		return http.StatusOK, wordpressLoginPage(failedLogin)
	case strings.HasPrefix(path, "/phpmyadmin") || strings.HasPrefix(path, "/pma"):
		return http.StatusOK, phpmyadminPage(failedLogin)
	case path == "/" || path == "/index.html":
		return http.StatusOK, defaultPage(h.server, h.cfg.Port)
	default:
		return http.StatusNotFound, errorPage(404, "Not Found", h.server)
	}
}

func (h *HTTPHoneypot) writeResponse(conn net.Conn, status int, contentType, body string) {
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn,
		"HTTP/1.1 %d %s\r\nDate: %s\r\nServer: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), time.Now().UTC().Format(http.TimeFormat),
		h.server, contentType, len(body), body)
}

func wordpressLoginPage(failed bool) string {
	errBox := ""
	if failed {
		errBox = `<div id="login_error"><strong>Error:</strong> The password you entered is incorrect.</div>`
	}
	return `<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
<title>Log In &lsaquo; WordPress &#8212; WordPress</title>
<style>
body{background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,sans-serif}
#login{width:320px;margin:100px auto 0}
#loginform{background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:26px 24px;margin-top:20px}
#login_error{background:#fff;border-left:4px solid #d63638;padding:12px;margin-top:20px}
input[type=text],input[type=password]{width:100%;padding:10px;margin-bottom:16px;box-sizing:border-box;border:1px solid #8c8f94;border-radius:4px}
input[type=submit]{background:#2271b1;color:#fff;border:none;padding:10px 16px;border-radius:4px;cursor:pointer;width:100%}
</style>
</head>
<body class="login">
<div id="login">
<h1>WordPress</h1>` + errBox + `
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address<br/>
<input type="text" name="log" id="user_login" autocapitalize="none" autocomplete="username" value="" size="20"/></label></p>
<p><label for="user_pass">Password<br/>
<input type="password" name="pwd" id="user_pass" autocomplete="current-password" size="20"/></label></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In"/></p>
<input type="hidden" name="redirect_to" value="/wp-admin/"/>
<input type="hidden" name="testcookie" value="1"/>
</form>
</div>
</body>
</html>`
}

func phpmyadminPage(failed bool) string {
	errBox := ""
	if failed {
		errBox = `<div class="error">#1045 - Access denied for user</div>`
	}
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>phpMyAdmin</title>
<style>
body{background:#f5f5f5;font-family:sans-serif}
#login_form{width:340px;margin:80px auto;background:#fff;padding:30px;border:1px solid #ddd;border-radius:4px}
h1{font-size:18px;margin-bottom:20px;text-align:center}
.error{color:#c00;margin-bottom:12px;font-size:13px}
label{display:block;margin-bottom:6px;font-size:13px}
input[type=text],input[type=password]{width:100%;padding:8px;margin-bottom:14px;box-sizing:border-box;border:1px solid #ccc;border-radius:3px}
input[type=submit]{background:#4285f4;color:#fff;border:none;padding:8px 16px;border-radius:3px;cursor:pointer}
</style>
</head>
<body>
<div id="login_form">
<h1>phpMyAdmin</h1>` + errBox + `
<form method="post" action="/phpmyadmin/index.php" name="login_form">
<label for="input_username">Username:</label>
<input type="text" name="pma_username" id="input_username" autocomplete="username"/>
<label for="input_password">Password:</label>
<input type="password" name="pma_password" id="input_password" autocomplete="current-password"/>
<input type="hidden" name="server" value="1"/>
<input type="submit" value="Go" id="input_go"/>
</form>
</div>
</body>
</html>`
}

func defaultPage(server string, port int) string {
	if strings.Contains(strings.ToLower(server), "nginx") {
		return `<!DOCTYPE html>
<html>
<head><title>Welcome to nginx!</title>
<style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>`
	}
	return `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
<title>Apache2 Ubuntu Default Page: It works</title>
<style type="text/css">body{background-color:#fff;color:#000}h1{background-color:#00f;color:#fff;padding:10px}</style>
</head>
<body>
<h1>It works!</h1>
<p>This is the default welcome page used to test the correct operation of the Apache2 server after installation on Ubuntu systems.</p>
<p>If you can read this page, it means that the Apache HTTP server installed at this site is working properly. You should <b>replace this file</b> before putting your website online.</p>
<hr/>
<address>` + html.EscapeString(server) + fmt.Sprintf(` Server at localhost Port %d</address>`, port) + `
</body>
</html>`
}

func errorPage(code int, text, server string) string {
	return fmt.Sprintf(`<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>%d %s</title>
</head><body>
<h1>%s</h1>
<hr>
<address>%s</address>
</body></html>`, code, text, text, html.EscapeString(server))
}
