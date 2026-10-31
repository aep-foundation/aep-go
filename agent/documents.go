package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	aep "github.com/aep-foundation/aep-go"
)

type DocumentReadOptions struct {
	Timeout time.Duration
}

type DocumentReadResult struct {
	Descriptor aep.ServiceDocument
	WebURL     string
	Document   *aep.PortableServiceDocument
	Reason     string
}

// ReadServiceDocument uses anonymous HTTPS or loopback HTTP independently of authenticated transports.
// A nil Document offers WebURL instead; caller cancellation and invalid options return an error.
func ReadServiceDocument(ctx context.Context, descriptor aep.ServiceDocument, options DocumentReadOptions) (DocumentReadResult, error) {
	transport := &http.Transport{
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer transport.CloseIdleConnections()
	return readServiceDocument(ctx, descriptor, options, transport)
}

func readServiceDocument(ctx context.Context, descriptor aep.ServiceDocument, options DocumentReadOptions, transport http.RoundTripper) (DocumentReadResult, error) {
	result := DocumentReadResult{Descriptor: descriptor}
	if err := aep.ValidateServiceDocument(descriptor); err != nil {
		return result, err
	}
	if options.Timeout < 0 {
		return result, errors.New("AEP document timeout must be positive")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	portableURL := ""
	for _, representation := range descriptor.Representations {
		switch representation.MediaType {
		case "text/html":
			result.WebURL = representation.URL
		case "application/json":
			portableURL = representation.URL
		}
	}
	if portableURL == "" {
		result.Reason = "not_advertised"
		return result, nil
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	document, err := downloadDocument(deadline, client, portableURL, descriptor.ID)
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		result.Reason = "unavailable_or_unsupported"
		return result, nil
	}
	result.Document = &document
	return result, nil
}

func downloadDocument(ctx context.Context, client *http.Client, location, id string) (aep.PortableServiceDocument, error) {
	for redirects := 0; ; redirects++ {
		if err := aep.ValidateDocumentURL(location); err != nil {
			return aep.PortableServiceDocument{}, err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
		if err != nil {
			return aep.PortableServiceDocument{}, err
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Accept-Encoding", "identity")
		request.Header["User-Agent"] = nil
		response, err := client.Do(request)
		if err != nil {
			return aep.PortableServiceDocument{}, err
		}
		switch response.StatusCode {
		case 301, 302, 303, 307, 308:
			_ = response.Body.Close()
			if redirects >= 5 {
				return aep.PortableServiceDocument{}, errors.New("AEP document redirect limit exceeded")
			}
			next, err := response.Location()
			if err != nil {
				return aep.PortableServiceDocument{}, err
			}
			if request.URL.Scheme == "https" && next.Scheme != "https" {
				return aep.PortableServiceDocument{}, errors.New("AEP document redirects must not downgrade HTTPS")
			}
			location = next.String()
			continue
		}
		document, err := readDocumentResponse(response, id)
		_ = response.Body.Close()
		return document, err
	}
}

func readDocumentResponse(response *http.Response, id string) (aep.PortableServiceDocument, error) {
	mediaType, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	encoding := response.Header.Get("Content-Encoding")
	if err != nil || response.StatusCode < 200 || response.StatusCode >= 300 || mediaType != "application/json" ||
		(parameters["charset"] != "" && !strings.EqualFold(parameters["charset"], "utf-8")) ||
		(encoding != "" && encoding != "identity") {
		return aep.PortableServiceDocument{}, errors.New("unsupported AEP document response")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, aep.MaxServiceDocumentBytes+1))
	if err != nil {
		return aep.PortableServiceDocument{}, err
	}
	if !utf8.Valid(data) {
		return aep.PortableServiceDocument{}, errors.New("AEP document is not valid UTF-8")
	}
	return aep.ParsePortableServiceDocument(data, id)
}
