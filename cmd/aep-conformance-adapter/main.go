package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type adapterRequest struct {
	Case struct {
		Expected map[string]json.RawMessage `json:"expected"`
		Input    map[string]json.RawMessage `json:"input"`
	} `json:"case"`
	Expectation string `json:"expectation"`
	Profile     string `json:"profile"`
	Role        string `json:"role"`
	Sequence    int    `json:"sequence"`
	Vector      struct {
		Category string `json:"category"`
		ID       string `json:"id"`
	} `json:"vector"`
}

type adapterResponse struct {
	Message         string `json:"message,omitempty"`
	ProtocolVersion string `json:"protocol_version"`
	Sequence        int    `json:"sequence"`
	Status          string `json:"status"`
}

func main() {
	role := ""
	if len(os.Args) == 2 {
		role = os.Args[1]
	}
	if role != "agent" && role != "platform" && role != "service" {
		failProcess("usage: aep-conformance-adapter agent|platform|service")
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var request adapterRequest
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			failProcess(err.Error())
		}
		if request.Role != role {
			failProcess("adapter request role does not match process role")
		}
		if err := encoder.Encode(evaluate(request)); err != nil {
			failProcess(err.Error())
		}
	}
	if err := scanner.Err(); err != nil {
		failProcess(err.Error())
	}
}

func evaluate(request adapterRequest) adapterResponse {
	response := adapterResponse{ProtocolVersion: "1", Sequence: request.Sequence}
	var passed bool
	var err error
	switch request.Role {
	case "agent":
		passed, err = evaluateAgent(request)
	case "platform":
		passed, err = evaluatePlatform(request)
	case "service":
		passed, err = evaluateService(request)
	}
	if err != nil {
		response.Status = "failed"
		response.Message = truncate(err.Error(), 1024)
		return response
	}
	if passed {
		response.Status = "passed"
	} else {
		response.Status = "failed"
		response.Message = "Public Go API result did not match the vector"
	}
	return response
}

func failProcess(message string) {
	_, _ = fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}

func truncate(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return value[:maximum]
}
