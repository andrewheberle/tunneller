package tunneller

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
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
			for header := range req.In.Header {
				if !slices.Contains(hdrs, header) {
					req.Out.Header.Del(header)
				}
			}

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
				rewritten, err := rewriteLocation(loc, prefix, target)
				if err == nil {
					resp.Header.Set("Location", rewritten)
				}
			}

			// Rewrite Set-Cookie Path attributes so cookies are scoped to the correct path
			rewriteCookiePaths(resp, prefix)

			// Rewrite absolute form action paths in HTML responses so that form
			// submissions are routed through the service prefix.
			if err := rewriteFormActions(resp, prefix); err != nil {
				return err
			}

			return nil
		},
	}

	return rp
}

// rewriteLocation rewrites a Location header value emitted by the endpoint so
// that it includes the service prefix. Relative paths are kept relative;
// absolute URLs pointing at the endpoint host are rewritten to the prefix path.
func rewriteLocation(loc, prefix string, target *url.URL) (string, error) {
	u, err := url.Parse(loc)
	if err != nil {
		return loc, fmt.Errorf("parse location %q: %w", loc, err)
	}

	// Absolute URL pointing at the endpoint - rewrite to our prefix
	if u.IsAbs() {
		if u.Host == target.Host {
			u.Scheme = ""
			u.Host = ""
			u.Path = prefix + "/" + strings.TrimPrefix(u.Path, "/")
			return u.String(), nil
		}
		// Absolute URL pointing elsewhere - leave untouched
		return loc, nil
	}

	// Relative path - prepend prefix
	if strings.HasPrefix(u.Path, "/") {
		u.Path = prefix + u.Path
		return u.String(), nil
	}

	return loc, nil
}

// rewriteCookiePaths rewrites the Path attribute of every Set-Cookie header in
// the response so that cookies are scoped to the service prefix rather than
// the endpoints own path hierarchy. This prevents cookies set at Path=/ on the
// endpoint from being sent to unrelated endpoint sessions on this service.
func rewriteCookiePaths(resp *http.Response, prefix string) {
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return
	}

	// Replace all Set-Cookie headers with rewritten versions
	resp.Header.Del("Set-Cookie")
	for _, c := range cookies {
		c.Path = prefix
		resp.Header.Add("Set-Cookie", c.String())
	}
}

// formActionRe matches form action attributes with single or double quoted
// absolute paths
var formActionRe = regexp.MustCompile(`action=(["'])(\/[^"']*)(["'])`)

// rewriteFormActions rewrites absolute path action attributes in HTML form
// tags so that form submissions include the service prefix. Only responses
// with a Content-Type of text/html are modified. The entire response body is
// buffered to perform the rewrite.
//
// Only absolute paths (e.g. action="/login.cgi") are rewritten; relative paths
// and full URLs are left untouched.
func rewriteFormActions(resp *http.Response, prefix string) error {
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("rewriteFormActions: read body: %w", err)
	}

	rewritten := formActionRe.ReplaceAllFunc(body, func(match []byte) []byte {
		sub := formActionRe.FindSubmatch(match)
		if len(sub) != 4 {
			return match
		}
		quote := sub[1]
		path := sub[2]

		newPath := append([]byte(prefix), path...)
		result := []byte("action=")
		result = append(result, quote...)
		result = append(result, newPath...)
		result = append(result, quote...)
		return result
	})

	resp.Body = io.NopCloser(bytes.NewReader(rewritten))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	resp.ContentLength = int64(len(rewritten))

	return nil
}
