package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	aep "github.com/aep-foundation/aep-go"
)

const DefaultMaximumRequestBodyBytes int64 = 1 << 20

const defaultInspectCacheControl = "public, max-age=300"

type HTTPHandlerOptions struct {
	InspectCacheControl     string
	MaximumRequestBodyBytes int64
}

type HTTPHandler struct {
	commandPaths            map[string]aep.Command
	inspectBody             []byte
	inspectCacheControl     string
	inspectETag             string
	maximumRequestBodyBytes int64
	service                 *Service
}

func NewHTTPHandler(service *Service, options HTTPHandlerOptions) (*HTTPHandler, error) {
	if service == nil {
		return nil, errors.New("AEP HTTP handler requires a Service")
	}
	if options.MaximumRequestBodyBytes < 0 {
		return nil, errors.New("AEP HTTP request body limit must not be negative")
	}
	if options.MaximumRequestBodyBytes == 0 {
		options.MaximumRequestBodyBytes = DefaultMaximumRequestBodyBytes
	}
	if options.InspectCacheControl == "" {
		options.InspectCacheControl = defaultInspectCacheControl
	}
	if strings.TrimSpace(options.InspectCacheControl) == "" || strings.ContainsAny(options.InspectCacheControl, "\r\n") {
		return nil, errors.New("AEP Inspect Cache-Control value must be a valid HTTP field value")
	}
	document, err := service.InspectDocument()
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(body)
	paths := make(map[string]aep.Command, len(document.Commands.Supported))
	for _, command := range document.Commands.Supported {
		if command == aep.CommandInspect {
			continue
		}
		path, pathErr := aep.CommandPathFromInspect(document, command)
		if pathErr != nil {
			return nil, pathErr
		}
		paths[path] = command
	}
	return &HTTPHandler{
		commandPaths: paths, inspectBody: body, inspectCacheControl: options.InspectCacheControl,
		inspectETag: `"sha256:` + hex.EncodeToString(digest[:]) + `"`, maximumRequestBodyBytes: options.MaximumRequestBodyBytes,
		service: service,
	}, nil
}

func (handler *HTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if handler == nil || handler.service == nil {
		writeHTTPProblem(response, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if request.URL.Path == aep.WellKnownPath {
		handler.serveInspect(response, request)
		return
	}
	command, found := handler.commandPaths[request.URL.Path]
	if !found {
		writeHTTPProblem(response, http.StatusNotFound, "Not Found")
		return
	}
	expectedMethod := http.MethodPost
	if command == aep.CommandStatus {
		expectedMethod = http.MethodGet
	}
	if request.Method != expectedMethod {
		response.Header().Set("Allow", expectedMethod)
		writeHTTPProblem(response, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}
	handler.serveCommand(response, request, command)
}

func (handler *HTTPHandler) serveInspect(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		writeHTTPProblem(response, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}
	response.Header().Set("Cache-Control", handler.inspectCacheControl)
	response.Header().Set("ETag", handler.inspectETag)
	if etagMatches(strings.Join(request.Header.Values("If-None-Match"), ","), handler.inspectETag) {
		response.WriteHeader(http.StatusNotModified)
		return
	}
	response.Header().Set("Content-Type", aep.MediaType)
	response.Header().Set("Content-Length", strconv.Itoa(len(handler.inspectBody)))
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(handler.inspectBody)
}

func (handler *HTTPHandler) serveCommand(response http.ResponseWriter, request *http.Request, command aep.Command) {
	options := CommandOptions{ClientAssertion: commandAssertion(request.Header)}
	var body []byte
	if command != aep.CommandStatus {
		contentType, uniqueContentType := singleHeaderValue(request.Header, "Content-Type")
		if !uniqueContentType || !matchesMediaType(contentType, aep.MediaType) {
			writeHTTPProblem(response, http.StatusUnsupportedMediaType, "Unsupported Media Type")
			return
		}
		options.IdempotencyKey, _ = singleHeaderValue(request.Header, "Idempotency-Key")
		var err error
		body, err = readRequestBody(response, request, handler.maximumRequestBodyBytes)
		if err != nil {
			var maximum *http.MaxBytesError
			if errors.As(err, &maximum) {
				writeHTTPProblem(response, http.StatusRequestEntityTooLarge, "Content Too Large")
				return
			}
			writeHTTPProblem(response, http.StatusBadRequest, "Bad Request")
			return
		}
	}

	switch command {
	case aep.CommandEnroll:
		result, err := handler.service.Enroll(request.Context(), body, options)
		writeServiceResult(response, result, err)
	case aep.CommandGrant:
		result, err := handler.service.Grant(request.Context(), body, options)
		writeServiceResult(response, result, err)
	case aep.CommandRevoke:
		result, err := handler.service.Revoke(request.Context(), body, options)
		writeServiceResult(response, result, err)
	case aep.CommandStatus:
		result, err := handler.service.Status(request.Context(), options)
		writeServiceResult(response, result, err)
	default:
		writeHTTPProblem(response, http.StatusNotFound, "Not Found")
	}
}

func NewProtectedResourceMiddleware(service *Service, resourceOrigin string) (func(http.Handler) http.Handler, error) {
	if service == nil {
		return nil, errors.New("AEP protected-resource middleware requires a Service")
	}
	origin, err := parseResourceOrigin(resourceOrigin, service.clientAssertion.AllowInsecureLoopback)
	if err != nil {
		return nil, err
	}
	return func(next http.Handler) http.Handler {
		if next == nil {
			next = http.NotFoundHandler()
		}
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			resource := *request.URL
			resource.Scheme = origin.Scheme
			resource.Host = origin.Host
			resource.User = nil
			resource.Fragment = ""
			result, authenticateErr := service.AuthenticateProtectedResource(request.Context(), ProtectedResourceRequest{
				Headers: request.Header, Method: request.Method, URL: &resource,
			})
			if authenticateErr != nil {
				writeHTTPProblem(response, http.StatusInternalServerError, "Internal Server Error")
				return
			}
			if !result.Authenticated {
				writeProblemResponse(response, result.Response)
				return
			}
			if result.Principal == nil {
				writeHTTPProblem(response, http.StatusInternalServerError, "Internal Server Error")
				return
			}
			ctx := context.WithValue(request.Context(), principalContextKey{}, clonePrincipal(*result.Principal))
			next.ServeHTTP(response, request.WithContext(ctx))
		})
	}, nil
}

func PrincipalFromContext(ctx context.Context) (AuthenticatedPrincipal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(AuthenticatedPrincipal)
	if !ok {
		return AuthenticatedPrincipal{}, false
	}
	return clonePrincipal(principal), true
}

type principalContextKey struct{}

type httpProblem struct {
	Status int    `json:"status"`
	Title  string `json:"title"`
	Type   string `json:"type"`
}

func readRequestBody(response http.ResponseWriter, request *http.Request, maximum int64) ([]byte, error) {
	if request.Body == nil {
		return nil, nil
	}
	defer request.Body.Close()
	return io.ReadAll(http.MaxBytesReader(response, request.Body, maximum))
}

func commandAssertion(header http.Header) string {
	value, unique := singleHeaderValue(header, "Authorization")
	if !unique {
		return ""
	}
	presentation, err := aep.ParseProtectedResourceAuthorization(value, aep.ProtectedResourceStandard)
	if err != nil || presentation.Scheme != aep.CredentialSchemeAEP {
		return ""
	}
	return presentation.Credentials
}

func singleHeaderValue(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func matchesMediaType(value string, expected string) bool {
	actual, _, err := mime.ParseMediaType(value)
	return err == nil && strings.EqualFold(actual, expected)
}

func etagMatches(value string, expected string) bool {
	for candidate := range strings.SplitSeq(value, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == expected || strings.TrimPrefix(candidate, "W/") == expected {
			return true
		}
	}
	return false
}

func parseResourceOrigin(value string, allowInsecureLoopback bool) (*url.URL, error) {
	origin, err := url.Parse(value)
	if err != nil || origin.Host == "" || origin.User != nil || origin.Opaque != "" || (origin.Path != "" && origin.Path != "/") || origin.ForceQuery || origin.RawQuery != "" || origin.Fragment != "" || strings.Contains(value, "#") {
		return nil, errors.New("AEP protected-resource origin must be an absolute origin without credentials, path, query, or fragment")
	}
	secure := origin.Scheme == "https"
	insecureLoopback := allowInsecureLoopback && origin.Scheme == "http" && isLoopbackHostname(origin.Hostname())
	if !secure && !insecureLoopback {
		return nil, errors.New("AEP protected-resource origin must use HTTPS")
	}
	origin.Path = ""
	return origin, nil
}

func writeServiceResult[Body any](response http.ResponseWriter, result Result[Body], err error) {
	if err != nil {
		writeHTTPProblem(response, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	body := any(result.Body)
	if result.Problem != nil {
		body = result.Problem
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		writeHTTPProblem(response, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	copyResponseHeaders(response.Header(), result.Headers)
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", result.ContentType)
	response.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	response.WriteHeader(result.Status)
	_, _ = response.Write(encoded)
}

func writeProblemResponse(response http.ResponseWriter, problem *ProblemResponse) {
	if problem == nil {
		writeHTTPProblem(response, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	encoded, err := json.Marshal(problem.Body)
	if err != nil {
		writeHTTPProblem(response, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	copyResponseHeaders(response.Header(), problem.Headers)
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", problem.ContentType)
	response.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	response.WriteHeader(problem.Status)
	_, _ = response.Write(encoded)
}

func writeHTTPProblem(response http.ResponseWriter, status int, title string) {
	encoded, _ := json.Marshal(httpProblem{Status: status, Title: title, Type: "about:blank"})
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", aep.ProblemMediaType)
	response.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

func copyResponseHeaders(destination http.Header, source http.Header) {
	for name, values := range source {
		if strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Content-Type") {
			continue
		}
		for _, value := range values {
			destination.Add(name, value)
		}
	}
}

func clonePrincipal(principal AuthenticatedPrincipal) AuthenticatedPrincipal {
	principal.Scopes = slices.Clone(principal.Scopes)
	return principal
}
