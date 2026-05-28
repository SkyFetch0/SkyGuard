package honeypot

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/skyguard/skyguard/internal/config"
)

// HTTPHoneypot simulates a generic HTTP server. It logs every requested path
// and returns believable HTML responses to attract and fingerprint scanners.
type HTTPHoneypot struct {
	cfg         config.HoneypotService
	eventLogger *EventLogger
	logger      *slog.Logger
}

// NewHTTPHoneypot creates an HTTPHoneypot.
func NewHTTPHoneypot(cfg config.HoneypotService, eventLogger *EventLogger, logger *slog.Logger) *HTTPHoneypot {
	if cfg.Banner == "" {
		cfg.Banner = "Apache/2.4.41 (Ubuntu)"
	}
	return &HTTPHoneypot{cfg: cfg, eventLogger: eventLogger, logger: logger}
}

// Type implements Handler.
func (h *HTTPHoneypot) Type() string { return "http" }

// Handle implements Handler.
// It reads the first line of the HTTP request to capture method and path,
// logs the attempt, and responds with a thematic HTML page.
func (h *HTTPHoneypot) Handle(conn net.Conn, sourceIP string) error {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	reader := bufio.NewReader(conn)

	// Read request line: "METHOD /path HTTP/1.x"
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		h.eventLogger.LogConnection(sourceIP, h.cfg.Port, "http", "")
		return fmt.Errorf("http: read request line: %w", err)
	}
	requestLine = strings.TrimSpace(requestLine)

	// Drain remaining headers to behave like a proper server.
	for {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		line, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}

	method, path, _ := parseRequestLine(requestLine)

	h.logger.Info("http request",
		"source_ip", sourceIP,
		"method", method,
		"path", path,
	)
	h.eventLogger.LogConnection(sourceIP, h.cfg.Port, "http",
		fmt.Sprintf("method=%s path=%s", method, path))

	body := h.selectBody(path)
	h.writeResponse(conn, http.StatusOK, body)

	return nil
}

// parseRequestLine splits "METHOD /path HTTP/1.x" into its three parts.
func parseRequestLine(line string) (method, path, proto string) {
	parts := strings.Fields(line)
	switch len(parts) {
	case 0:
		return "", "/", ""
	case 1:
		return parts[0], "/", ""
	case 2:
		return parts[0], parts[1], ""
	default:
		return parts[0], parts[1], parts[2]
	}
}

// selectBody returns an appropriate fake HTML body for the requested path.
func (h *HTTPHoneypot) selectBody(path string) string {
	lower := strings.ToLower(path)
	switch {
	case lower == "/admin" || lower == "/wp-admin" || lower == "/wp-admin/" ||
		lower == "/wp-login.php" || strings.HasPrefix(lower, "/wp-admin/"):
		return wordpressLoginPage()
	case strings.HasPrefix(lower, "/phpmyadmin"):
		return phpmyadminPage()
	default:
		return apacheDefaultPage()
	}
}

// writeResponse sends a minimal HTTP/1.1 200 OK response.
func (h *HTTPHoneypot) writeResponse(conn net.Conn, statusCode int, body string) {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	statusText := http.StatusText(statusCode)
	response := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\nServer: %s\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		statusCode, statusText, h.cfg.Banner, len(body), body,
	)
	fmt.Fprint(conn, response)
}

// wordpressLoginPage returns a stripped-down WordPress login form.
func wordpressLoginPage() string {
	return `<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
<title>Log In &lsaquo; WordPress &#8212; WordPress</title>
<style>
body{background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,sans-serif}
#login{width:320px;margin:100px auto 0}
h1 a{background:url(https://wordpress.org/about/images/logos/wordpress-logo-notext-rgb.png) no-repeat top;width:84px;height:84px;display:block;margin:0 auto 25px;text-indent:-9999px}
#loginform{background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:26px 24px;margin-top:20px}
input[type=text],input[type=password]{width:100%;padding:10px;margin-bottom:16px;box-sizing:border-box;border:1px solid #8c8f94;border-radius:4px}
input[type=submit]{background:#2271b1;color:#fff;border:none;padding:10px 16px;border-radius:4px;cursor:pointer;width:100%}
</style>
</head>
<body class="login">
<div id="login">
<h1><a href="https://wordpress.org/" title="Powered by WordPress" tabindex="-1">WordPress</a></h1>
<form name="loginform" id="loginform" action="wp-login.php" method="post">
<p><label for="user_login">Username or Email Address<br/>
<input type="text" name="log" id="user_login" autocapitalize="none" autocomplete="username" value="" size="20"/></label></p>
<p><label for="user_pass">Password<br/>
<input type="password" name="pwd" id="user_pass" autocomplete="current-password" size="20"/></label></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In"/></p>
<input type="hidden" name="redirect_to" value="wp-admin/"/>
<input type="hidden" name="testcookie" value="1"/>
</form>
</div>
</body>
</html>`
}

// phpmyadminPage returns a minimal phpMyAdmin login page.
func phpmyadminPage() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>phpMyAdmin</title>
<style>
body{background:#f5f5f5;font-family:sans-serif}
#pma_navigation_header{background:#f0f0f0;padding:10px}
#login_form{width:340px;margin:80px auto;background:#fff;padding:30px;border:1px solid #ddd;border-radius:4px}
h1{font-size:18px;margin-bottom:20px;text-align:center}
label{display:block;margin-bottom:6px;font-size:13px}
input[type=text],input[type=password]{width:100%;padding:8px;margin-bottom:14px;box-sizing:border-box;border:1px solid #ccc;border-radius:3px}
input[type=submit]{background:#4285f4;color:#fff;border:none;padding:8px 16px;border-radius:3px;cursor:pointer}
</style>
</head>
<body>
<div id="login_form">
<h1>phpMyAdmin</h1>
<form method="post" action="index.php" name="login_form">
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

// apacheDefaultPage returns an Apache 2 default page.
func apacheDefaultPage() string {
	return `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
<title>Apache2 Ubuntu Default Page: It works</title>
<style type="text/css">
body{background-color:#fff;color:#000}h1{background-color:#00f;color:#fff;padding:10px}
</style>
</head>
<body>
<h1>It works!</h1>
<p>This is the default welcome page used to test the correct operation of the Apache2 server after installation on Ubuntu systems.</p>
<p>If you can read this page, it means that the Apache HTTP server installed at this site is working properly. You should <b>replace this file</b> before putting your website online.</p>
<hr/>
<address>Apache/2.4.41 (Ubuntu) Server at localhost Port 80</address>
</body>
</html>`
}