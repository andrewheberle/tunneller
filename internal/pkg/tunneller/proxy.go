package tunneller

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
)

// ProxyHandler returns an http.Handler that proxies requests to the endpoint
// over the provided tunnel. prefix is the path prefix to strip before
// forwarding and hdrs is a list of allowed headers
func (t *Tunnel) ProxyHandler(prefix string, hdrs []string) http.Handler {

	target := &url.URL{
		Scheme: t.endpointScheme,
		Host:   t.endpointAddr,
	}

	rp := &httputil.ReverseProxy{
		Transport: t.transport(),
		Rewrite: func(req *httputil.ProxyRequest) {
			req.Out.URL.Scheme = target.Scheme
			req.Out.URL.Host = target.Host

			// strip out headers we don't want to pass to the endpoint
			t.filterHeaders(req, hdrs)

			// filter any cookies
			t.filterCookies(req)

			// Strip the prefix so the endpoint sees its own paths
			trimmed := strings.TrimPrefix(req.In.URL.Path, prefix)
			if trimmed == "" {
				trimmed = "/"
			}
			req.Out.URL.Path = trimmed

			// Keep RawPath consistent if it was set
			if req.In.URL.RawPath != "" {
				rawTrimmed := strings.TrimPrefix(req.In.URL.RawPath, prefix)
				if rawTrimmed == "" {
					rawTrimmed = "/"
				}
				req.Out.URL.RawPath = rawTrimmed
			}

			// Do not pass the incoming Host header; let the endpoint see its own host
			req.Out.Host = target.Host
		},
		ModifyResponse: func(resp *http.Response) error {
			// Rewrite Location headers so redirects stay within our prefix
			if loc := resp.Header.Get("Location"); loc != "" {
				rewritten, err := t.rewriteLocation(loc, prefix)
				if err == nil {
					resp.Header.Set("Location", rewritten)
				}
			}

			// Rewrite Set-Cookie Path attributes so cookies are scoped to the correct path
			// and also track any cookies sent back
			t.rewriteCookiePaths(resp, prefix)

			// Rewrite absolute form action paths in HTML responses so that form
			// submissions are routed through the service prefix.
			if err := t.rewriteContent(resp, prefix); err != nil {
				return err
			}

			return nil
		},
	}

	return rp
}

// rewriteLocation rewrites a Location header value emitted by the endpoint so
// that it includes the service prefix. Relative paths are kept relative;
// absolute URLs are rewritten to the prefix path.
func (t *Tunnel) rewriteLocation(loc, prefix string) (string, error) {
	u, err := url.Parse(loc)
	if err != nil {
		return loc, fmt.Errorf("parse location %q: %w", loc, err)
	}

	// Absolute URL - rewrite to our prefix
	if u.IsAbs() {
		u.Scheme = ""
		u.Host = ""
		p, err := url.JoinPath(prefix, u.Path)
		if err != nil {
			return loc, err
		}
		u.Path = p
		return u.String(), nil
	}

	// Relative path - prepend prefix (only if not already present)
	if strings.HasPrefix(u.Path, "/") && !strings.HasPrefix(u.Path, prefix) {
		p, err := url.JoinPath(prefix, u.Path)
		if err != nil {
			return loc, err
		}
		u.Path = p
		return u.String(), nil
	}

	return loc, nil
}

// rewriteCookiePaths rewrites the Path attribute of every Set-Cookie header in
// the response so that cookies are scoped to the service prefix rather than
// the endpoints own path hierarchy. This prevents cookies set at Path=/ on the
// endpoint from being sent to unrelated endpoint sessions on this service.
func (t *Tunnel) rewriteCookiePaths(resp *http.Response, prefix string) {
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return
	}

	// Replace all Set-Cookie headers with rewritten versions
	resp.Header.Del("Set-Cookie")
	for _, c := range cookies {
		c.Path = prefix
		resp.Header.Add("Set-Cookie", c.String())

		// record cookie
		if t.key != "" && t.tracker != nil {
			t.logger.Debug("tracked cookie", "key", t.key, "name", c.Name)
			t.tracker.Record(t.key, c.Name)
		}
	}
}

// rewriteContent rewrites absolute path action attributes in HTML form
// tags so that form submissions include the service prefix. Only responses
// with a Content-Type of text/html are modified. The entire response body is
// buffered to perform the rewrite.
//
// Only absolute paths (e.g. action="/login.cgi") are rewritten; relative paths
// and full URLs are left untouched.
func (t *Tunnel) rewriteContent(resp *http.Response, prefix string) error {
	var body []byte

	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		// handle ,issing content type by sniffing for mime type
		if err := func() error {
			b, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return fmt.Errorf("read body: %w", err)
			}
			body = b

			// detect content type and set header
			ct = http.DetectContentType(body)
			resp.Header.Set("Content-Type", ct)

			t.logger.Debug("response did not include a content-type header so value was detected", "detected", ct)

			return nil
		}(); err != nil {
			return fmt.Errorf("rewriteFormActions: sniff content type: %w", err)
		}
	}
	if !strings.HasPrefix(ct, "text/html") {
		return nil
	}

	// read body if not already read
	if body == nil {
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("rewriteFormActions: read body: %w", err)
		}
		body = b
	}

	rewritten := body
	for _, rewrite := range t.rewriteContentRules {
		rewritten = rewrite.re.ReplaceAllFunc(rewritten, func(match []byte) []byte {
			subs := rewrite.re.FindSubmatch(match)
			if len(subs) != 2 {
				panic(fmt.Sprintf("regexp %q must have exactly one capture group", rewrite.re.String()))
			}

			captured := subs[1]
			replacement := rewrite.transform(prefix, captured)

			// Reconstruct: preserve surrounding non-captured parts of the match
			idx := bytes.Index(match, captured)
			if idx < 0 {
				return match
			}
			return append(append(match[:idx:idx], replacement...), match[idx+len(captured):]...)
		})

	}

	resp.Body = io.NopCloser(bytes.NewReader(rewritten))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	resp.ContentLength = int64(len(rewritten))

	return nil
}

func (t *Tunnel) filterHeaders(req *httputil.ProxyRequest, hdrs []string) {
	// strip out headers we don't want to pass to the endpoint
	for header := range req.In.Header {
		if !slices.Contains(hdrs, header) {
			req.Out.Header.Del(header)
		}
	}
}

func (t *Tunnel) filterCookies(req *httputil.ProxyRequest) {
	// skip of tracker is not set up
	if t.key == "" || t.tracker == nil {
		return
	}

	// skip of no cookies set
	cookies := req.In.Cookies()
	if len(cookies) == 0 {
		return
	}

	// delete outbound cookie header
	req.Out.Header.Del("Cookie")

	// find any tracked cookies and add back
	for _, c := range cookies {
		if t.tracker.Found(t.key, c.Name) {
			req.Out.Header.Add("Cookie", c.String())
			continue
		}

		t.logger.Debug("dropped untracked cookie", "key", t.key, "name", c.Name)
	}
}
