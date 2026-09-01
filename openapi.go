package aep

import (
	"errors"
	"net/url"
	"strings"
)

type OpenAPIPathMatchOptions struct {
	Method        string
	Path          string
	TrailingSlash string
}

type OpenAPIPathMatch struct {
	Method   string
	Template string
}

func MatchOpenAPIPath(templates []string, options OpenAPIPathMatchOptions) (OpenAPIPathMatch, error) {
	method := strings.ToUpper(options.Method)
	if method == "" || options.Path == "" || strings.Contains(options.Path, "?") {
		return OpenAPIPathMatch{}, errors.New("invalid OpenAPI operation target")
	}
	if options.TrailingSlash != "strict" && options.TrailingSlash != "equivalent" {
		return OpenAPIPathMatch{}, errors.New("invalid OpenAPI trailing-slash policy")
	}
	requestSegments := openAPIPathSegments(options.Path, options.TrailingSlash)
	best := ""
	bestSpecificity := ""
	ambiguous := false
	for _, template := range templates {
		templateSegments := openAPIPathSegments(template, options.TrailingSlash)
		if len(templateSegments) != len(requestSegments) {
			continue
		}
		specificity := make([]byte, len(templateSegments))
		matched := true
		for index, segment := range templateSegments {
			if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") && len(segment) > 2 {
				specificity[index] = '0'
				continue
			}
			specificity[index] = '1'
			if segment != requestSegments[index] {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		score := string(specificity)
		if best == "" || score > bestSpecificity {
			best, bestSpecificity = template, score
			ambiguous = false
			continue
		}
		if score == bestSpecificity {
			ambiguous = true
		}
	}
	if best == "" {
		return OpenAPIPathMatch{}, errors.New("OpenAPI operation is not documented")
	}
	if ambiguous {
		return OpenAPIPathMatch{}, errors.New("ambiguous OpenAPI path templates")
	}
	return OpenAPIPathMatch{Method: method, Template: best}, nil
}

func ResolveOpenAPIURL(finalInspectURL string, reference string, allowInsecureLoopback bool) (*url.URL, error) {
	base, err := url.Parse(finalInspectURL)
	if err != nil || base == nil || base.Host == "" || base.User != nil ||
		base.Scheme != "https" && !(allowInsecureLoopback && base.Scheme == "http" && openAPILoopbackHost(base.Hostname())) {
		return nil, errors.New("invalid final AEP Inspect URL")
	}
	referenceURL, err := url.Parse(reference)
	if err != nil || referenceURL == nil {
		return nil, errors.New("invalid AEP OpenAPI URL")
	}
	resolved := base.ResolveReference(referenceURL)
	if resolved.User != nil || resolved.Fragment != "" || resolved.Host == "" {
		return nil, errors.New("invalid AEP OpenAPI URL")
	}
	if resolved.Scheme != "https" && !(allowInsecureLoopback && resolved.Scheme == "http" && openAPILoopbackHost(resolved.Hostname())) {
		return nil, errors.New("AEP OpenAPI URL requires HTTPS")
	}
	return resolved, nil
}

func openAPIPathSegments(path string, trailingSlash string) []string {
	if trailingSlash == "equivalent" && path != "/" {
		path = strings.TrimSuffix(path, "/")
	}
	return strings.Split(strings.TrimPrefix(path, "/"), "/")
}

func openAPILoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
