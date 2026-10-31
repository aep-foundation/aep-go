package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	aep "github.com/aep-foundation/aep-go"
)

const portableDocumentBody = `{"format":"aep-service-document","version":"1.0","id":"terms","content":[{"type":"paragraph","text":"Full terms."}]}`

func readDescriptor() aep.ServiceDocument {
	return aep.ServiceDocument{ID: "terms", Title: "Terms", Type: "terms_of_service", Enrollment: "required", Representations: []aep.DocumentRepresentation{
		{MediaType: "text/html", URL: "https://example.com/terms"},
		{MediaType: "application/json", URL: "https://example.com/terms.json"},
	}}
}

func documentTestTransport(t *testing.T, handler http.HandlerFunc) (*http.Transport, *atomic.Int32) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	calls := &atomic.Int32{}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			calls.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{RootCAs: roots, ServerName: server.Certificate().DNSNames[0], MinVersion: tls.VersionTLS12},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return transport, calls
}

func TestDocumentRetrievalAnonymousTLSAndRedirects(t *testing.T) {
	var requests atomic.Int32
	transport, connections := documentTestTransport(t, func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method != "GET" || request.ContentLength != 0 || request.Header.Get("Accept") != "application/json" || request.Header.Get("Accept-Encoding") != "identity" {
			t.Errorf("unexpected request: %#v", request)
		}
		for key := range request.Header {
			if key != "Accept" && key != "Accept-Encoding" && key != "Connection" {
				t.Errorf("unexpected identifying header: %s", key)
			}
		}
		if request.URL.Path == "/terms.json" {
			response.Header().Set("Set-Cookie", "session=must-not-forward")
			http.Redirect(response, request, "https://legal.example.net/document", 302)
			return
		}
		if request.Host != "legal.example.net" {
			t.Errorf("wrong redirect host: %s", request.Host)
		}
		response.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = io.WriteString(response, portableDocumentBody)
	})
	result, err := readServiceDocument(context.Background(), readDescriptor(), DocumentReadOptions{}, transport)
	if err != nil || result.Document == nil || result.Reason != "" || result.WebURL != "https://example.com/terms" || requests.Load() != 2 || connections.Load() != 2 {
		t.Fatalf("unexpected retrieval: %#v, %v, requests=%d", result, err, requests.Load())
	}
}

func TestDocumentRetrievalFallsBackWithoutPartialContent(t *testing.T) {
	for _, test := range []struct {
		name, body, contentType, encoding, redirect string
		status                                      int
	}{
		{name: "missing", status: 404},
		{name: "wrong media", contentType: "text/html", body: portableDocumentBody},
		{name: "wrong charset", contentType: "application/json; charset=iso-8859-1", body: portableDocumentBody},
		{name: "compression", encoding: "gzip", body: portableDocumentBody},
		{name: "oversize", body: strings.Repeat(" ", aep.MaxServiceDocumentBytes+1)},
		{name: "wrong id", body: strings.ReplaceAll(portableDocumentBody, `"terms"`, `"other"`)},
		{name: "unknown block", body: strings.ReplaceAll(portableDocumentBody, `"paragraph"`, `"table"`)},
		{name: "invalid utf8", body: portableDocumentBody + string([]byte{255})},
		{name: "truncated", body: portableDocumentBody[:40]},
		{name: "HTTPS downgrade", redirect: "http://127.0.0.1/document"},
		{name: "http redirect", redirect: "http://example.com/document"},
		{name: "userinfo redirect", redirect: "https://user@example.com/document"},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport, calls := documentTestTransport(t, func(response http.ResponseWriter, request *http.Request) {
				if test.redirect != "" {
					http.Redirect(response, request, test.redirect, 307)
					return
				}
				contentType := test.contentType
				if contentType == "" {
					contentType = "application/json"
				}
				response.Header().Set("Content-Type", contentType)
				if test.encoding != "" {
					response.Header().Set("Content-Encoding", test.encoding)
				}
				if test.status != 0 {
					response.WriteHeader(test.status)
				}
				_, _ = io.WriteString(response, test.body)
			})
			result, err := readServiceDocument(context.Background(), readDescriptor(), DocumentReadOptions{}, transport)
			if err != nil || result.Document != nil || result.Reason != "unavailable_or_unsupported" || result.WebURL == "" || calls.Load() != 1 {
				t.Fatalf("unsafe or missing fallback: %#v, %v, calls=%d", result, err, calls.Load())
			}
		})
	}
}

func TestDocumentRetrievalRedirectLimitAndSizeBoundary(t *testing.T) {
	for _, redirects := range []int{5, 6} {
		var calls atomic.Int32
		transport, _ := documentTestTransport(t, func(response http.ResponseWriter, request *http.Request) {
			if int(calls.Add(1)) <= redirects {
				http.Redirect(response, request, "/next", 308)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, portableDocumentBody+strings.Repeat(" ", aep.MaxServiceDocumentBytes-len(portableDocumentBody)))
		})
		result, err := readServiceDocument(context.Background(), readDescriptor(), DocumentReadOptions{}, transport)
		if err != nil || (result.Document != nil) != (redirects == 5) || calls.Load() != 6 {
			t.Fatalf("redirect limit %d: %#v, %v", redirects, result, err)
		}
	}
}

func TestDocumentRetrievalCancellationAndTimeout(t *testing.T) {
	for _, cancellation := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		transport, _ := documentTestTransport(t, func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, "{")
			response.(http.Flusher).Flush()
			if cancellation {
				cancel()
			}
			<-request.Context().Done()
		})
		result, err := readServiceDocument(ctx, readDescriptor(), DocumentReadOptions{Timeout: 100 * time.Millisecond}, transport)
		cancel()
		if cancellation {
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation hidden: %v", err)
			}
		} else if err != nil || result.Document != nil || result.Reason != "unavailable_or_unsupported" {
			t.Fatalf("timeout result: %#v %v", result, err)
		}
	}
}

func TestDocumentRetrievalRejectsInvalidTLS(t *testing.T) {
	for _, failure := range []string{"untrusted certificate", "wrong hostname"} {
		t.Run(failure, func(t *testing.T) {
			var requests atomic.Int32
			transport, _ := documentTestTransport(t, func(response http.ResponseWriter, request *http.Request) {
				requests.Add(1)
			})
			if failure == "untrusted certificate" {
				transport.TLSClientConfig.RootCAs = x509.NewCertPool()
			} else {
				transport.TLSClientConfig.ServerName = "wrong.invalid"
			}
			result, err := readServiceDocument(context.Background(), readDescriptor(), DocumentReadOptions{}, transport)
			if err != nil || result.Document != nil || result.Reason != "unavailable_or_unsupported" || requests.Load() != 0 {
				t.Fatalf("invalid TLS accepted: %#v %v requests=%d", result, err, requests.Load())
			}
		})
	}
}

func TestDocumentPublicReaderValidation(t *testing.T) {
	descriptor := readDescriptor()
	descriptor.Representations = descriptor.Representations[:1]
	result, err := ReadServiceDocument(context.Background(), descriptor, DocumentReadOptions{})
	if err != nil || result.Document != nil || result.Reason != "not_advertised" {
		t.Fatalf("link-only: %#v %v", result, err)
	}
	if _, err := ReadServiceDocument(context.Background(), descriptor, DocumentReadOptions{Timeout: -1}); err == nil {
		t.Fatal("accepted negative timeout")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadServiceDocument(ctx, descriptor, DocumentReadOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	descriptor.ID = ""
	if _, err := ReadServiceDocument(context.Background(), descriptor, DocumentReadOptions{}); err == nil {
		t.Fatal("accepted invalid descriptor")
	}
}

func TestDocumentPublicReaderLocalDevelopment(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Header.Get("Cookie") != "" || request.Header.Get("Authorization") != "" {
			t.Error("credentials reached document endpoint")
		}
		if request.URL.Path == "/terms" {
			response.Header().Set("Set-Cookie", "session=not-forwarded")
			http.Redirect(response, request, "/document", http.StatusFound)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, portableDocumentBody)
	}))
	defer server.Close()
	for _, origin := range []string{server.URL, strings.Replace(server.URL, "127.0.0.1", "localhost", 1)} {
		descriptor := readDescriptor()
		descriptor.Representations[1].URL = origin + "/terms"
		result, err := ReadServiceDocument(context.Background(), descriptor, DocumentReadOptions{})
		if err != nil || result.Document == nil {
			t.Fatalf("local HTTP failed: %#v %v", result, err)
		}
	}
	if requests.Load() != 4 {
		t.Fatalf("expected local redirects, requests=%d", requests.Load())
	}
}

func TestDocumentHTTPSDoesNotFilterDestinationAddress(t *testing.T) {
	transport, _ := documentTestTransport(t, func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, portableDocumentBody)
	})
	descriptor := readDescriptor()
	descriptor.Representations[1].URL = "https://127.0.0.1/document"
	result, err := readServiceDocument(context.Background(), descriptor, DocumentReadOptions{}, transport)
	if err != nil || result.Document == nil {
		t.Fatalf("HTTPS address was rejected: %#v %v", result, err)
	}
}
