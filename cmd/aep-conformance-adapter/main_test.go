package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvaluateSharedVector(t *testing.T) {
	request := adapterRequest{Role: "agent", Sequence: 7}
	request.Vector.Category = "claims"
	request.Vector.ID = "minimal-email"
	request.Case.Input = map[string]json.RawMessage{
		"claim_values": json.RawMessage(`{"contact.email":"a@b"}`),
	}
	request.Case.Expected = map[string]json.RawMessage{
		"valid": json.RawMessage(`true`),
	}

	response := evaluate(request)
	if response.Status != "passed" || response.Sequence != 7 || response.ProtocolVersion != "1" {
		t.Fatalf("unexpected adapter response: %#v", response)
	}
}

func TestEvaluateUnknownVectorFails(t *testing.T) {
	request := adapterRequest{Role: "service"}
	request.Vector.Category = "unknown"
	request.Vector.ID = "unknown"

	response := evaluate(request)
	if response.Status != "failed" || !strings.Contains(response.Message, "no Service operation maps vector") {
		t.Fatalf("unexpected adapter response: %#v", response)
	}
}

func TestAgentResponseVectorsUseCommandClient(t *testing.T) {
	for _, category := range []string{"enroll", "status", "grant-revoke"} {
		t.Run(category, func(t *testing.T) {
			request := adapterRequest{Role: "agent"}
			request.Vector.Category, request.Vector.ID = category, "response-active"
			body := json.RawMessage(`{"status":"active"}`)
			if category == "grant-revoke" {
				request.Vector.ID, body = "revoke-response-empty", json.RawMessage(`{}`)
			}
			request.Case.Expected = map[string]json.RawMessage{
				"status": json.RawMessage(`200`), "content_type": json.RawMessage(`"application/aep+json"`), "body": body,
			}
			if result := evaluate(request); result.Status != "passed" {
				t.Fatalf("%#v", result)
			}
			request.Case.Expected["content_type"] = json.RawMessage(`"text/html"`)
			if evaluate(request).Status == "passed" {
				t.Fatal("accepted incorrect success media type")
			}
			request.Case.Expected["content_type"] = json.RawMessage(`"application/aep+json"`)
			request.Case.Expected["status"] = json.RawMessage(`403`)
			if evaluate(request).Status == "passed" {
				t.Fatal("accepted failure as command success")
			}
		})
	}
	request := adapterRequest{Role: "agent"}
	request.Vector.Category, request.Vector.ID = "errors", "not-recognized-problem"
	request.Case.Expected = map[string]json.RawMessage{
		"status": json.RawMessage(`404`), "content_type": json.RawMessage(`"application/problem+json"`),
		"body": json.RawMessage(`{"type":"urn:aep:error:not_recognized","title":"Not recognized","status":404,"code":"not_recognized"}`),
	}
	if result := evaluate(request); result.Status != "passed" {
		t.Fatalf("%#v", result)
	}
	request.Case.Expected["status"] = json.RawMessage(`200`)
	if evaluate(request).Status == "passed" {
		t.Fatal("accepted successful response as typed command error")
	}
}

func TestServiceResponseVectorsObserveGeneratedHTTPResponse(t *testing.T) {
	for _, test := range []struct{ category, id, body, status, media string }{
		{"enroll", "response-active", `{"status":"active"}`, `200`, `"application/aep+json"`},
		{"enroll", "response-pending-verification-owner-action", `{"status":"pending","owner_action_required":"true","verification_pending":["contact.email"]}`, `200`, `"application/aep+json"`},
		{"errors", "requirements-unmet-problem", `{"type":"urn:aep:error:requirements_unmet","title":"Requirements unmet","code":"requirements_unmet","status":422,"requirements_pending":["company.registration"]}`, `422`, `"application/problem+json"`},
		{"grant-revoke", "revoke-response-empty", `{}`, `200`, `"application/aep+json"`},
	} {
		t.Run(test.id, func(t *testing.T) {
			request := adapterRequest{Role: "service"}
			request.Vector.Category, request.Vector.ID = test.category, test.id
			request.Case.Expected = map[string]json.RawMessage{"body": json.RawMessage(test.body), "status": json.RawMessage(test.status), "content_type": json.RawMessage(test.media)}
			if result := evaluate(request); result.Status != "passed" {
				t.Fatalf("%#v", result)
			}
			for field, wrong := range map[string]json.RawMessage{"body": json.RawMessage(`{}`), "status": json.RawMessage(`201`), "content_type": json.RawMessage(`"text/html"`)} {
				if field == "body" && test.body == `{}` {
					wrong = json.RawMessage(`{"unexpected":true}`)
				}
				original := request.Case.Expected[field]
				request.Case.Expected[field] = wrong
				if evaluate(request).Status == "passed" {
					t.Fatalf("ignored %s", field)
				}
				request.Case.Expected[field] = original
			}
		})
	}
}

func TestGrantResponseVectorsExerciseIssuanceAndConsumption(t *testing.T) {
	for _, role := range []string{"agent", "service"} {
		for grant, fields := range map[string]string{
			"api-key":      `"api_key":"secret","header":"x-api-key"`,
			"basic":        `"username":"user","password":"secret","realm":"example"`,
			"oauth-bearer": `"access_token":"secret","token_type":"Bearer"`,
		} {
			t.Run(role+"/"+grant, func(t *testing.T) {
				request := adapterRequest{Role: role}
				request.Vector.Category, request.Vector.ID = "credentials/"+grant, "grant-response"
				if err := json.Unmarshal([]byte(`{"credential_id":"credential","expires_at":"2026-12-01T00:00:00Z",`+fields+`}`), &request.Case.Expected); err != nil {
					t.Fatal(err)
				}
				if result := evaluate(request); result.Status != "passed" {
					t.Fatalf("%#v", result)
				}
				delete(request.Case.Expected, "credential_id")
				if evaluate(request).Status == "passed" {
					t.Fatal("accepted missing credential identifier")
				}
				request.Vector.ID = "grant-response-missing-credential-id"
				request.Case.Input = request.Case.Expected
				request.Case.Expected = map[string]json.RawMessage{"valid": json.RawMessage(`false`)}
				if result := evaluate(request); result.Status != "passed" {
					t.Fatalf("missing identifier was not rejected at Grant: %#v", result)
				}
			})
		}
	}
}

func TestAuthenticationAdvertisementsUseServiceAndAgent(t *testing.T) {
	for _, role := range []string{"agent", "service"} {
		request := adapterRequest{Role: role}
		request.Vector.ID = "inspect-authentication-methods"
		request.Case.Expected = map[string]json.RawMessage{
			"jwt_only":         json.RawMessage(`{"authentication":{"methods":["aep-jwt"]}}`),
			"credentials_only": json.RawMessage(`{"authentication":{"methods":["oauth-bearer","api-key","basic"]}}`),
			"ordered_mixed":    json.RawMessage(`{"authentication":{"methods":["aep-jwt","oauth-bearer","api-key","basic"]}}`),
			"omitted_means":    json.RawMessage(`"no-advertised-method"`),
		}
		if response := evaluate(request); response.Status != "passed" {
			t.Fatalf("%s: %#v", role, response)
		}
		request.Case.Expected["ordered_mixed"] = json.RawMessage(`{"authentication":{"methods":["basic","api-key","oauth-bearer","aep-jwt"]}}`)
		if response := evaluate(request); response.Status != "passed" {
			t.Fatalf("%s: reordered preference lost: %#v", role, response)
		}
		request.Case.Expected["omitted_means"] = json.RawMessage(`"jwt-default"`)
		if evaluate(request).Status == "passed" {
			t.Fatalf("%s: ignored omitted-method expectation", role)
		}
	}
}

func TestCommandVectorsUseWireExpectations(t *testing.T) {
	for _, role := range []string{"agent", "service"} {
		for _, command := range []string{"enroll", "grant", "revoke"} {
			t.Run(role+"/"+command, func(t *testing.T) {
				request := adapterRequest{Role: role}
				request.Vector.ID = "grant-request-oauth-bearer"
				request.Case.Input = map[string]json.RawMessage{"grant_type": json.RawMessage(`"oauth-bearer"`)}
				request.Case.Expected = map[string]json.RawMessage{
					"method": json.RawMessage(`"POST"`), "path": json.RawMessage(`"/aep/` + command + `"`),
					"content_type": json.RawMessage(`"application/aep+json"`), "authorization_scheme": json.RawMessage(`"AEP"`),
					"client_assertion_op": json.RawMessage(`"` + command + `"`), "body": json.RawMessage(`{"grant_type":"oauth-bearer"}`),
				}
				if command == "enroll" {
					request.Vector.ID = "request-minimal"
					request.Case.Input = map[string]json.RawMessage{
						"agent_did": json.RawMessage(`"did:web:agent.example.com:agents:123"`),
						"claims":    json.RawMessage(`{"contact.email":"owner@example.com"}`), "idempotency_key": json.RawMessage(`"enroll-vector"`),
					}
					delete(request.Case.Expected, "body")
					request.Case.Expected["idempotency_key"] = json.RawMessage(`"enroll-vector"`)
				} else if command == "revoke" {
					request.Vector.ID = "revoke-request-all-grant-types"
					request.Case.Input = map[string]json.RawMessage{"all_grant_types": json.RawMessage(`"true"`)}
					request.Case.Expected["body"] = json.RawMessage(`{"all_grant_types":"true"}`)
					request.Case.Expected["must_not_contain"] = json.RawMessage(`["grant_type","credential_id"]`)
				}
				if response := evaluate(request); response.Status != "passed" {
					t.Fatalf("%#v", response)
				}
				for field, original := range request.Case.Expected {
					wrong := json.RawMessage(`"incorrect"`)
					if field == "must_not_contain" {
						wrong = json.RawMessage(`["all_grant_types"]`)
					}
					request.Case.Expected[field] = wrong
					if evaluate(request).Status == "passed" {
						t.Fatalf("ignored %s", field)
					}
					request.Case.Expected[field] = original
				}
			})
		}
	}
}

func TestCredentialPresentationsExerciseAgentAndService(t *testing.T) {
	for _, role := range []string{"agent", "service"} {
		t.Run(role, func(t *testing.T) {
			request := adapterRequest{Role: role}
			request.Vector.ID = "credential-presentations"
			request.Case.Input = map[string]json.RawMessage{"resource": json.RawMessage(`"https://api.example.com/v1/orders"`)}
			request.Case.Expected = map[string]json.RawMessage{
				"oauth-bearer": json.RawMessage(`{"header":"Authorization","scheme":"Bearer"}`),
				"api-key":      json.RawMessage(`{"header":"x-api-key","value":"opaque-api-key"}`),
				"basic":        json.RawMessage(`{"header":"Authorization","scheme":"Basic"}`),
			}
			if response := evaluate(request); response.Status != "passed" {
				t.Fatalf("%#v", response)
			}
			for field, wrong := range map[string]json.RawMessage{
				"oauth-bearer": json.RawMessage(`{"header":"Authorization","scheme":"Basic"}`),
				"api-key":      json.RawMessage(`{"header":"other-key","value":"opaque-api-key"}`),
				"basic":        json.RawMessage(`{"header":"Authorization","scheme":"Bearer"}`),
			} {
				original := request.Case.Expected[field]
				request.Case.Expected[field] = wrong
				if evaluate(request).Status == "passed" {
					t.Fatalf("ignored presentation for %s", field)
				}
				delete(request.Case.Expected, field)
				if evaluate(request).Status == "passed" {
					t.Fatalf("accepted missing %s", field)
				}
				request.Case.Expected[field] = original
			}
			request.Case.Expected["api-key"] = json.RawMessage(`{"header":"x-api-key","value":"different"}`)
			if evaluate(request).Status == "passed" {
				t.Fatal("ignored API-key value")
			}
			request.Case.Expected["api-key"] = json.RawMessage(`{"header":"x-api-key","value":"opaque-api-key"}`)
			request.Case.Input["resource"] = json.RawMessage(`"https://other.example/private"`)
			if evaluate(request).Status == "passed" {
				t.Fatal("accepted cross-origin credential presentation")
			}
		})
	}
}

func TestServiceGrantBeforeEnrollmentUsesExpectations(t *testing.T) {
	request := adapterRequest{Role: "service"}
	request.Vector.ID = "grant-before-enroll-rejected"
	request.Case.Input = map[string]json.RawMessage{"operation": json.RawMessage(`"grant"`), "enrollment": json.RawMessage(`"unrecognized"`)}
	request.Case.Expected = map[string]json.RawMessage{"status": json.RawMessage(`401`), "code": json.RawMessage(`"not_recognized"`), "implicit_enrollment": json.RawMessage(`false`)}
	if response := evaluate(request); response.Status != "passed" {
		t.Fatalf("%#v", response)
	}
	for field, wrong := range map[string]json.RawMessage{"status": json.RawMessage(`403`), "code": json.RawMessage(`"unsupported_grant_type"`), "implicit_enrollment": json.RawMessage(`true`)} {
		original := request.Case.Expected[field]
		request.Case.Expected[field] = wrong
		if evaluate(request).Status == "passed" {
			t.Fatalf("ignored %s", field)
		}
		delete(request.Case.Expected, field)
		if evaluate(request).Status == "passed" {
			t.Fatalf("accepted missing %s", field)
		}
		request.Case.Expected[field] = original
	}
}

func TestServiceEnrollmentConflictUsesVector(t *testing.T) {
	request := adapterRequest{Role: "service"}
	request.Vector.ID = "enroll-conflict"
	request.Case.Input = map[string]json.RawMessage{
		"agent_did":        json.RawMessage(`"did:web:agent.example.com:agents:123"`),
		"idempotency_key":  json.RawMessage(`"conflict-key"`),
		"first_body_hash":  json.RawMessage(`"sha256:first"`),
		"second_body_hash": json.RawMessage(`"sha256:second"`),
	}
	request.Case.Expected = map[string]json.RawMessage{
		"status": json.RawMessage(`409`), "content_type": json.RawMessage(`"application/problem+json"`),
		"body": json.RawMessage(`{"type":"urn:aep:error:idempotency_conflict","title":"Idempotency conflict","status":409,"code":"idempotency_conflict"}`),
	}
	if response := evaluate(request); response.Status != "passed" {
		t.Fatalf("%#v", response)
	}
	for field, wrong := range map[string]json.RawMessage{"status": json.RawMessage(`400`), "content_type": json.RawMessage(`"application/aep+json"`), "body": json.RawMessage(`{"code":"invalid_request"}`)} {
		original := request.Case.Expected[field]
		request.Case.Expected[field] = wrong
		if evaluate(request).Status == "passed" {
			t.Fatalf("ignored %s", field)
		}
		delete(request.Case.Expected, field)
		if evaluate(request).Status == "passed" {
			t.Fatalf("accepted missing %s", field)
		}
		request.Case.Expected[field] = original
	}
	for field, original := range request.Case.Input {
		delete(request.Case.Input, field)
		if evaluate(request).Status == "passed" {
			t.Fatalf("accepted missing input %s", field)
		}
		request.Case.Input[field] = original
	}
	request.Case.Input["second_body_hash"] = request.Case.Input["first_body_hash"]
	if evaluate(request).Status == "passed" {
		t.Fatal("reported conflict for identical request hashes")
	}
}

func TestClaimNegotiationUsesSubmittedClaimsAndExpectations(t *testing.T) {
	for _, role := range []string{"agent", "service"} {
		t.Run(role, func(t *testing.T) {
			request := adapterRequest{Role: role}
			request.Vector.ID = "negotiation-compatibility"
			request.Case.Input = map[string]json.RawMessage{
				"inspect":   json.RawMessage(`{"required":["contact.email"],"preferred":["example.future.preferred"],"optional":["example.future.optional"]}`),
				"submitted": json.RawMessage(`{"contact.email":"owner@example.com","example.unadvertised":"extra"}`),
			}
			request.Case.Expected = map[string]json.RawMessage{
				"enrollment_requirement_satisfied": json.RawMessage(`true`),
				"omitted_preferred_allowed":        json.RawMessage(`true`),
				"unknown_optional_action":          json.RawMessage(`"ignore"`),
				"unknown_preferred_action":         json.RawMessage(`"ignore"`),
				"unknown_submitted_default_action": json.RawMessage(`"ignore"`),
			}
			if response := evaluate(request); response.Status != "passed" {
				t.Fatalf("%#v", response)
			}
			for field, original := range request.Case.Expected {
				request.Case.Expected[field] = json.RawMessage(`false`)
				if evaluate(request).Status == "passed" {
					t.Fatalf("ignored %s", field)
				}
				delete(request.Case.Expected, field)
				if evaluate(request).Status == "passed" {
					t.Fatalf("accepted missing %s", field)
				}
				request.Case.Expected[field] = original
			}
			for _, submitted := range []string{`{"example.unadvertised":"extra"}`, `{"contact.email":42}`} {
				request.Case.Input["submitted"] = json.RawMessage(submitted)
				if evaluate(request).Status == "passed" {
					t.Fatalf("accepted unsatisfied claims: %s", submitted)
				}
			}
		})
	}
}

func TestAssertionValidationUsesInputsAndRejectionList(t *testing.T) {
	for _, role := range []string{"agent", "service"} {
		t.Run(role, func(t *testing.T) {
			request := adapterRequest{Role: role}
			request.Vector.ID = "validation-requirements"
			request.Case.Input = map[string]json.RawMessage{
				"agent_did":   json.RawMessage(`"did:web:agent.example.com:agents:123"`),
				"service_did": json.RawMessage(`"did:web:api.example.com"`),
				"algorithm":   json.RawMessage(`"ES256"`),
				"issued_at":   json.RawMessage(`1748428800`),
				"expires_at":  json.RawMessage(`1748428860`),
				"jti":         json.RawMessage(`"assertion-vector"`),
			}
			request.Case.Expected = map[string]json.RawMessage{
				"claims": json.RawMessage(`{"aud":"did:web:api.example.com","exp":1748428860,"iat":1748428800,"iss":"did:web:agent.example.com:agents:123","sub":"did:web:agent.example.com:agents:123","jti":"assertion-vector","op":"enroll"}`),
				"header": json.RawMessage(`{"alg":"ES256","kid":"did:web:agent.example.com:agents:123","typ":"JWT"}`),
				"reject": json.RawMessage(`["excessive_lifetime","fragmented_resource","insecure_resource","mismatched_kid","mismatched_subject","missing_kid","missing_resource","nonpositive_lifetime","unexpected_resource","wrong_typ"]`),
			}
			if response := evaluate(request); response.Status != "passed" {
				t.Fatalf("%#v", response)
			}
			request.Case.Input["jti"] = json.RawMessage(`"different-assertion"`)
			if evaluate(request).Status == "passed" {
				t.Fatal("built assertion from expected claims instead of input")
			}
			request.Case.Input["jti"] = json.RawMessage(`"assertion-vector"`)
			for field, original := range request.Case.Expected {
				delete(request.Case.Expected, field)
				if evaluate(request).Status == "passed" {
					t.Fatalf("accepted missing %s", field)
				}
				request.Case.Expected[field] = original
			}
			for _, rejected := range []string{`[]`, `["unknown"]`, `["wrong_typ","wrong_typ"]`} {
				request.Case.Expected["reject"] = json.RawMessage(rejected)
				if evaluate(request).Status == "passed" {
					t.Fatalf("accepted incomplete or invalid rejection list: %s", rejected)
				}
			}
		})
	}
}

func TestClaimCatalogValidatesValues(t *testing.T) {
	for _, role := range []string{"agent", "service"} {
		t.Run(role, func(t *testing.T) {
			request := adapterRequest{Role: role}
			request.Vector.ID = "person-contact-catalog"
			request.Case.Expected = map[string]json.RawMessage{
				"contact.address.primary": json.RawMessage(`{"city":"San Francisco","country":"US","first_name":"Grace","last_name":"Hopper","line1":"123 Market Street","line3":"Attention: Receiving","postcode":"94105","region":"CA"}`),
				"contact.email":           json.RawMessage(`"owner@example.com"`),
				"contact.mobile":          json.RawMessage(`"+14155550100"`),
				"person.birthdate":        json.RawMessage(`"1990-04-12"`),
				"person.first_name":       json.RawMessage(`"Ada"`),
				"person.last_name":        json.RawMessage(`"Lovelace"`),
				"person.username":         json.RawMessage(`"ada"`),
			}
			if response := evaluate(request); response.Status != "passed" {
				t.Fatalf("%#v", response)
			}
			for field, original := range request.Case.Expected {
				request.Case.Expected[field] = json.RawMessage(`42`)
				if evaluate(request).Status == "passed" {
					t.Fatalf("ignored %s value", field)
				}
				request.Case.Expected[field] = original
			}
		})
	}
}

func TestOpenAPISecurityUsesExpectedMappings(t *testing.T) {
	for _, role := range []string{"agent", "service"} {
		t.Run(role, func(t *testing.T) {
			request := adapterRequest{Role: role}
			request.Vector.ID = "security-inheritance"
			request.Case.Input = map[string]json.RawMessage{"security_scheme": json.RawMessage(`{"type":"http","scheme":"AEP","x-aep-authentication-method":"aep-jwt"}`)}
			request.Case.Expected = map[string]json.RawMessage{
				"root_inherited":                json.RawMessage(`"required"`),
				"operation_empty_array":         json.RawMessage(`"public"`),
				"empty_requirement_alternative": json.RawMessage(`"optional-anonymous"`),
				"multiple_objects":              json.RawMessage(`"alternatives"`),
				"multiple_schemes_one_object":   json.RawMessage(`"all-required"`),
				"unsupported_compound":          json.RawMessage(`"fallback-live-challenge"`),
			}
			if response := evaluate(request); response.Status != "passed" {
				t.Fatalf("%#v", response)
			}
			for field, original := range request.Case.Expected {
				request.Case.Expected[field] = json.RawMessage(`"incorrect"`)
				if evaluate(request).Status == "passed" {
					t.Fatalf("ignored %s", field)
				}
				request.Case.Expected[field] = original
			}
		})
	}
}

func TestOpenAPIPathMatchingUsesExpectedResults(t *testing.T) {
	for _, role := range []string{"agent", "service"} {
		t.Run(role, func(t *testing.T) {
			request := adapterRequest{Role: role}
			request.Vector.ID = "path-matching"
			request.Case.Input = map[string]json.RawMessage{
				"method":    json.RawMessage(`"get"`),
				"path":      json.RawMessage(`"/v1/orders/123"`),
				"query":     json.RawMessage(`"view=full"`),
				"templates": json.RawMessage(`["/v1/orders/{id}","/v1/{kind}/123"]`),
			}
			request.Case.Expected = map[string]json.RawMessage{
				"method":                  json.RawMessage(`"GET"`),
				"query_selects_operation": json.RawMessage(`false`),
				"literal_precedence":      json.RawMessage(`true`),
				"strict":                  json.RawMessage(`{"/items":"different-from-/items/"}`),
				"equivalent":              json.RawMessage(`{"/items":"same-as-/items/","/":"unchanged"}`),
				"similar_templates":       json.RawMessage(`"contradiction"`),
				"stale_contradiction":     json.RawMessage(`"revalidate-and-live-challenge"`),
			}
			if response := evaluate(request); response.Status != "passed" {
				t.Fatalf("%#v", response)
			}
			request.Case.Input["templates"] = json.RawMessage(`["/v1/{kind}/123","/v1/orders/{id}"]`)
			if response := evaluate(request); response.Status != "passed" {
				t.Fatalf("template order changed matching: %#v", response)
			}
			for field, value := range map[string]json.RawMessage{
				"method":                  json.RawMessage(`"POST"`),
				"query_selects_operation": json.RawMessage(`true`),
				"literal_precedence":      json.RawMessage(`false`),
				"strict":                  json.RawMessage(`{"/items":"same-as-/items/"}`),
				"equivalent":              json.RawMessage(`{"/items":"different-from-/items/","/":"unchanged"}`),
				"similar_templates":       json.RawMessage(`"pick-first"`),
				"stale_contradiction":     json.RawMessage(`"trust-cache"`),
			} {
				original := request.Case.Expected[field]
				request.Case.Expected[field] = value
				if evaluate(request).Status == "passed" {
					t.Fatalf("ignored %s", field)
				}
				delete(request.Case.Expected, field)
				if evaluate(request).Status == "passed" {
					t.Fatalf("accepted missing %s", field)
				}
				request.Case.Expected[field] = original
			}
			request.Case.Expected["equivalent"] = json.RawMessage(`{"/items":"same-as-/items/","/":"trimmed"}`)
			if evaluate(request).Status == "passed" {
				t.Fatal("ignored root slash expectation")
			}
		})
	}
}

func TestOpenAPIURLExercisesAnonymousRetrieval(t *testing.T) {
	for _, role := range []string{"agent", "service"} {
		t.Run(role, func(t *testing.T) {
			request := adapterRequest{Role: role}
			request.Vector.ID = "url-resolution"
			request.Case.Input = map[string]json.RawMessage{
				"final_inspect_url": json.RawMessage(`"https://api.example.com/discovery/aep"`),
				"relative":          json.RawMessage(`"../openapi.json"`),
				"cross_origin":      json.RawMessage(`"https://docs.example.net/openapi.json"`),
			}
			request.Case.Expected = map[string]json.RawMessage{
				"relative_resolved":    json.RawMessage(`"https://api.example.com/openapi.json"`),
				"cross_origin_https":   json.RawMessage(`"allowed-anonymous"`),
				"forwarded_headers":    json.RawMessage(`[]`),
				"userinfo":             json.RawMessage(`"reject"`),
				"downgrade":            json.RawMessage(`"reject"`),
				"accepted_media_types": json.RawMessage(`["application/vnd.oai.openapi+json;version=3.1","application/json"]`),
			}
			if response := evaluate(request); response.Status != "passed" {
				t.Fatalf("%#v", response)
			}
			for field, value := range map[string]json.RawMessage{
				"relative_resolved":    json.RawMessage(`"https://api.example.com/wrong.json"`),
				"cross_origin_https":   json.RawMessage(`"forbidden"`),
				"forwarded_headers":    json.RawMessage(`["Authorization"]`),
				"userinfo":             json.RawMessage(`"allow"`),
				"downgrade":            json.RawMessage(`"allow"`),
				"accepted_media_types": json.RawMessage(`["text/plain"]`),
			} {
				original := request.Case.Expected[field]
				request.Case.Expected[field] = value
				if evaluate(request).Status == "passed" {
					t.Fatalf("ignored %s", field)
				}
				request.Case.Expected[field] = original
			}
		})
	}
}

func TestPlatformIdempotencyExercisesOperations(t *testing.T) {
	request := adapterRequest{Role: "platform"}
	request.Vector.ID = "idempotency-replay-conflict"
	request.Case.Input = map[string]json.RawMessage{
		"principal":        json.RawMessage(`"another-stable-principal"`),
		"initial_sign_key": json.RawMessage(`"initial-sign"`),
		"final_sign_key":   json.RawMessage(`"final-sign"`),
		"operations":       json.RawMessage(`["provision","sign","hosted_verification"]`),
	}
	request.Case.Expected = map[string]json.RawMessage{
		"retention_seconds_minimum":         json.RawMessage(`"3600"`),
		"exact_replay":                      json.RawMessage(`"stored_http_result"`),
		"changed_input_or_operation_status": json.RawMessage(`409`),
		"changed_input_or_operation_code":   json.RawMessage(`"idempotency_conflict"`),
	}
	if response := evaluate(request); response.Status != "passed" {
		t.Fatalf("%#v", response)
	}
	for _, operation := range []string{"provision", "sign", "hosted_verification"} {
		t.Run(operation, func(t *testing.T) {
			encoded, err := json.Marshal([]string{operation})
			if err != nil {
				t.Fatal(err)
			}
			request.Case.Input["operations"] = encoded
			if response := evaluate(request); response.Status != "passed" {
				t.Fatalf("%#v", response)
			}
			for field, value := range map[string]json.RawMessage{
				"retention_seconds_minimum":         json.RawMessage(`"7200"`),
				"exact_replay":                      json.RawMessage(`"body_only"`),
				"changed_input_or_operation_status": json.RawMessage(`400`),
				"changed_input_or_operation_code":   json.RawMessage(`"invalid_request"`),
			} {
				original := request.Case.Expected[field]
				request.Case.Expected[field] = value
				if evaluate(request).Status == "passed" {
					t.Fatalf("accepted incorrect %s", field)
				}
				request.Case.Expected[field] = original
			}
		})
	}
	request.Case.Input["final_sign_key"] = request.Case.Input["initial_sign_key"]
	if evaluate(request).Status == "passed" {
		t.Fatal("accepted the same key for changed completion input")
	}
	request.Case.Input["final_sign_key"] = json.RawMessage(`"final-sign"`)
	request.Case.Input["operations"] = json.RawMessage(`["unknown"]`)
	if evaluate(request).Status == "passed" {
		t.Fatal("accepted unknown operation")
	}
}

func TestPlatformAuthorizationExercisesPrivateOperations(t *testing.T) {
	request := adapterRequest{Role: "platform"}
	request.Vector.ID = "authorization-required"
	request.Case.Input = map[string]json.RawMessage{"private_operations": json.RawMessage(`["get-identity","list-identities","provision-identity","sign","update-identity","verify"]`)}
	request.Case.Expected = map[string]json.RawMessage{
		"did_document_public":      json.RawMessage(`true`),
		"management_denied_code":   json.RawMessage(`"not_recognized"`),
		"management_denied_status": json.RawMessage(`404`),
		"missing_authorizer":       json.RawMessage(`"construction-error"`),
		"side_effects":             json.RawMessage(`false`),
		"verification_denied":      json.RawMessage(`{"reason":"not_recognized","verified":false}`),
	}
	if response := evaluate(request); response.Status != "passed" {
		t.Fatalf("%#v", response)
	}
	for field, value := range map[string]json.RawMessage{
		"management_denied_status": json.RawMessage(`403`),
		"verification_denied":      json.RawMessage(`{"reason":"verified","verified":true}`),
	} {
		original := request.Case.Expected[field]
		request.Case.Expected[field] = value
		if evaluate(request).Status == "passed" {
			t.Fatalf("accepted incorrect %s", field)
		}
		request.Case.Expected[field] = original
	}
	request.Case.Input["private_operations"] = json.RawMessage(`["unknown"]`)
	if evaluate(request).Status == "passed" {
		t.Fatal("accepted unknown operation")
	}
}

func TestPlatformSignChecksMetadataAndSignature(t *testing.T) {
	request := adapterRequest{Role: "platform"}
	request.Vector.ID = "sign-response"
	if err := json.Unmarshal([]byte(`{"agent_did":"did:web:p.example:a:4Yf7p2xQd9","client_assertion":"illustrative","expires_at":"2026-07-06T12:05:00Z","issued_at":"2026-07-06T12:00:00Z","jti":"01J0AEPASSERTION0000000001","platform_context":{"authorization_handle":"opaque-value"},"service_did":"did:web:api.service.example","status":"completed"}`), &request.Case.Expected); err != nil {
		t.Fatal(err)
	}
	if response := evaluate(request); response.Status != "passed" {
		t.Fatalf("%#v", response)
	}
	for field, value := range map[string]json.RawMessage{
		"service_did":      json.RawMessage(`"did:web:wrong.example"`),
		"expires_at":       json.RawMessage(`"2026-07-06T12:04:00Z"`),
		"platform_context": json.RawMessage(`{"authorization_handle":"different"}`),
	} {
		original := request.Case.Expected[field]
		request.Case.Expected[field] = value
		if evaluate(request).Status == "passed" {
			t.Fatalf("accepted incorrect %s", field)
		}
		request.Case.Expected[field] = original
	}
}

func TestPlatformVerificationComparesCompleteResponse(t *testing.T) {
	for _, recognized := range []bool{true, false} {
		request := adapterRequest{Role: "platform"}
		request.Vector.ID = "verification-response-unrecognized"
		request.Case.Expected = map[string]json.RawMessage{
			"verified":    json.RawMessage(`false`),
			"reason":      json.RawMessage(`"not_recognized"`),
			"service_did": json.RawMessage(`"did:web:api.service.example"`),
		}
		if recognized {
			request.Vector.ID = "verification-response-recognized"
			request.Case.Expected["verified"] = json.RawMessage(`true`)
			request.Case.Expected["reason"] = json.RawMessage(`"verified"`)
			request.Case.Expected["agent_did"] = json.RawMessage(`"did:web:p.example:a:4Yf7p2xQd9"`)
			request.Case.Expected["agent_identity_id"] = json.RawMessage(`"pai_01J0AEPPLATFORM000000000001"`)
			request.Case.Expected["op"] = json.RawMessage(`"enroll"`)
			request.Case.Expected["status"] = json.RawMessage(`"active"`)
		}
		if response := evaluate(request); response.Status != "passed" {
			t.Fatalf("%s: %#v", request.Vector.ID, response)
		}
		request.Case.Expected["service_did"] = json.RawMessage(`"did:web:wrong.example"`)
		if evaluate(request).Status == "passed" {
			t.Fatal("ignored an incorrect Service DID in verification output")
		}
	}
}

func TestServiceDIDBindingRejectsBeforeIdentityUse(t *testing.T) {
	request := adapterRequest{Role: "agent"}
	request.Vector.ID = "service-did-origin-binding"
	request.Case.Input = map[string]json.RawMessage{
		"inspect_url":             json.RawMessage(`"https://api.example.com/.well-known/aep"`),
		"matching_service_did":    json.RawMessage(`"did:web:api.example.com:services:primary"`),
		"mismatched_service_did":  json.RawMessage(`"did:web:other.example.com"`),
		"unsupported_service_did": json.RawMessage(`"did:key:example"`),
	}
	request.Case.Expected = map[string]json.RawMessage{
		"matching_service_did":    json.RawMessage(`"accept"`),
		"mismatched_service_did":  json.RawMessage(`"service_identity_mismatch"`),
		"unsupported_service_did": json.RawMessage(`"service_identity_mismatch"`),
		"provision_identity":      json.RawMessage(`false`),
		"request_assertion":       json.RawMessage(`false`),
		"transmit_credentials":    json.RawMessage(`false`),
	}
	for _, role := range []string{"agent", "service"} {
		request.Role = role
		if response := evaluate(request); response.Status != "passed" {
			t.Fatalf("%s: %#v", role, response)
		}
	}
	for _, name := range []string{"mismatched_service_did", "unsupported_service_did"} {
		original := request.Case.Input[name]
		request.Case.Input[name] = request.Case.Input["matching_service_did"]
		if evaluate(request).Status == "passed" {
			t.Fatalf("claimed rejection of a matching DID in %s", name)
		}
		request.Case.Input[name] = original
	}
	request.Case.Input["matching_service_did"] = request.Case.Input["mismatched_service_did"]
	if evaluate(request).Status == "passed" {
		t.Fatal("claimed acceptance of a mismatched DID")
	}
}

func TestServiceCommandHeaderExercisesAllCommands(t *testing.T) {
	request := adapterRequest{Role: "service"}
	request.Vector.ID = "command-header"
	request.Case.Input = map[string]json.RawMessage{
		"commands":        json.RawMessage(`["enroll","grant","revoke"]`),
		"idempotency_key": json.RawMessage(`"header-test"`),
	}
	request.Case.Expected = map[string]json.RawMessage{
		"enroll_body_key":               json.RawMessage(`"optional"`),
		"header_required":               json.RawMessage(`true`),
		"mismatched_enroll_body_status": json.RawMessage(`400`),
		"missing_or_empty_code":         json.RawMessage(`"invalid_request"`),
		"missing_or_empty_status":       json.RawMessage(`400`),
	}
	if response := evaluate(request); response.Status != "passed" {
		t.Fatalf("%#v", response)
	}
	for field, value := range map[string]json.RawMessage{
		"enroll_body_key":               json.RawMessage(`"required"`),
		"header_required":               json.RawMessage(`false`),
		"mismatched_enroll_body_status": json.RawMessage(`200`),
		"missing_or_empty_code":         json.RawMessage(`"not_recognized"`),
		"missing_or_empty_status":       json.RawMessage(`401`),
	} {
		t.Run(field, func(t *testing.T) {
			original := request.Case.Expected[field]
			request.Case.Expected[field] = value
			if evaluate(request).Status == "passed" {
				t.Fatal("accepted an incorrect header expectation")
			}
			request.Case.Expected[field] = original
		})
	}
	request.Case.Input["commands"] = json.RawMessage(`["status"]`)
	if evaluate(request).Status == "passed" {
		t.Fatal("accepted an unsupported command")
	}
}

func TestServiceReplayConflictObservesExecution(t *testing.T) {
	request := adapterRequest{Role: "service"}
	request.Vector.ID = "command-replay-conflict"
	request.Case.Input = map[string]json.RawMessage{
		"agent_did":        json.RawMessage(`"did:web:agent.example.com:agents:123"`),
		"idempotency_key":  json.RawMessage(`"retry-test"`),
		"first_command":    json.RawMessage(`"grant"`),
		"second_command":   json.RawMessage(`"revoke"`),
		"first_body_hash":  json.RawMessage(`"sha256:first"`),
		"second_body_hash": json.RawMessage(`"sha256:second"`),
	}
	request.Case.Expected = map[string]json.RawMessage{
		"retention_seconds_minimum": json.RawMessage(`3600`),
		"scope":                     json.RawMessage(`["agent_did","idempotency_key"]`),
		"exact_retry":               json.RawMessage(`"cached_or_equivalent_success"`),
		"changed_body":              json.RawMessage(`{"status":409,"code":"idempotency_conflict"}`),
		"changed_command":           json.RawMessage(`{"status":409,"code":"idempotency_conflict"}`),
	}
	if response := evaluate(request); response.Status != "passed" {
		t.Fatalf("%#v", response)
	}
	for _, name := range []string{"changed_body", "changed_command"} {
		original := request.Case.Expected[name]
		request.Case.Expected[name] = json.RawMessage(`{"status":400,"code":"invalid_request"}`)
		if evaluate(request).Status == "passed" {
			t.Fatalf("accepted incorrect %s response", name)
		}
		request.Case.Expected[name] = original
	}
	request.Case.Input["second_body_hash"] = request.Case.Input["first_body_hash"]
	if evaluate(request).Status == "passed" {
		t.Fatal("claimed a body conflict for identical bodies")
	}
}

func TestServiceFieldSafetyObservesCarrierAndCache(t *testing.T) {
	request := adapterRequest{Role: "service"}
	request.Vector.ID = "authorization-field-safety"
	request.Case.Input = map[string]json.RawMessage{"field_name": json.RawMessage(`"aep-authorization"`)}
	request.Case.Expected = map[string]json.RawMessage{
		"field_name_match":                 json.RawMessage(`"case-insensitive"`),
		"sensitive_headers_redacted":       json.RawMessage(`true`),
		"cache_key_excluded":               json.RawMessage(`true`),
		"idempotency_fingerprint_excluded": json.RawMessage(`true`),
	}
	for _, field := range []string{"aep-authorization", "AeP-AuThOrIzAtIoN"} {
		request.Case.Input["field_name"], _ = json.Marshal(field)
		if response := evaluate(request); response.Status != "passed" {
			t.Fatalf("%s: %#v", field, response)
		}
	}
	request.Case.Input["field_name"] = json.RawMessage(`"x-unrecognized"`)
	if evaluate(request).Status == "passed" {
		t.Fatal("accepted an unrelated authorization field")
	}
}

func TestServiceAuthenticateAssertionUsesServiceVerification(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		value string
	}{
		{name: "valid"},
		{name: "wrong audience", field: "aud", value: "did:web:other.example"},
		{name: "wrong resource", field: "resource", value: "https://service.example/other"},
		{name: "wrong operation", field: "op", value: "status"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := adapterRequest{Role: "service"}
			request.Vector.ID = "authenticate-assertion"
			request.Case.Input = map[string]json.RawMessage{"method": json.RawMessage(`"GET"`), "url": json.RawMessage(`"https://service.example/private"`)}
			claims := map[string]any{
				"iss": "did:web:agent.example", "sub": "did:web:agent.example", "aud": "did:web:service.example",
				"op": "authenticate", "resource": "https://service.example/private", "iat": 1783958400, "exp": 1783958460, "jti": "resource-test",
			}
			if test.field != "" {
				claims[test.field] = test.value
			}
			encoded, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			request.Case.Expected = map[string]json.RawMessage{
				"claims": encoded, "authorization_scheme": json.RawMessage(`"AEP"`),
				"challenge": json.RawMessage(`{"scheme":"AEP","service_did":"did:web:service.example","inspect":"https://service.example/.well-known/aep","reason":"authentication_required"}`),
			}
			response := evaluate(request)
			if (response.Status == "passed") != (test.name == "valid") {
				t.Fatalf("unexpected conformance result: %#v", response)
			}
		})
	}
}

func TestServiceTransportInvokesInspectHandler(t *testing.T) {
	for _, test := range []struct {
		name      string
		url       string
		mediaType string
		passed    bool
	}{
		{"Inspect", "https://service.example/.well-known/aep", "application/aep+json", true},
		{"missing route", "https://service.example/not-inspect", "application/aep+json", false},
		{"wrong expected media type", "https://service.example/.well-known/aep", "text/html", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := adapterRequest{Role: "service"}
			request.Vector.ID = "transport-requirements"
			requestURL, _ := json.Marshal(test.url)
			mediaType, _ := json.Marshal(test.mediaType)
			request.Case.Input = map[string]json.RawMessage{"request_url": requestURL}
			request.Case.Expected = map[string]json.RawMessage{"media_type_essence": mediaType}
			response := evaluate(request)
			if (response.Status == "passed") != test.passed {
				t.Fatalf("unexpected transport result: %#v", response)
			}
		})
	}
}

func TestServiceOperationBindingExecutesEveryPair(t *testing.T) {
	for _, test := range []struct {
		name    string
		allowed string
		failure string
		passed  bool
	}{
		{"valid", `["enroll:enroll","grant:grant","revoke:revoke","status:status","authenticate:protected-resource"]`, `"not_recognized"`, true},
		{"missing allowed pair", `["enroll:enroll","grant:grant","revoke:revoke","status:status"]`, `"not_recognized"`, false},
		{"incorrect allowed pair", `["enroll:enroll","grant:grant","revoke:revoke","status:status","enroll:protected-resource"]`, `"not_recognized"`, false},
		{"wrong rejection", `["enroll:enroll","grant:grant","revoke:revoke","status:status","authenticate:protected-resource"]`, `"authentication_required"`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := adapterRequest{Role: "service"}
			request.Vector.ID = "operation-substitution-rejected"
			request.Case.Input = map[string]json.RawMessage{
				"operations":         json.RawMessage(`["enroll","grant","revoke","status","authenticate"]`),
				"command_endpoints":  json.RawMessage(`["enroll","grant","revoke","status"]`),
				"protected_resource": json.RawMessage(`"https://service.example/orders"`),
			}
			request.Case.Expected = map[string]json.RawMessage{"allowed": json.RawMessage(test.allowed), "all_other_pairs": json.RawMessage(test.failure)}
			response := evaluate(request)
			if (response.Status == "passed") != test.passed {
				t.Fatalf("unexpected operation matrix result: %#v", response)
			}
		})
	}
}

func TestServicePaymentCompositionUsesMiddleware(t *testing.T) {
	request := adapterRequest{Role: "service"}
	request.Vector.ID = "authorization-payment-composition"
	request.Case.Input = map[string]json.RawMessage{"anonymous_status": json.RawMessage(`401`), "anonymous_challenge": json.RawMessage(`"AEP"`)}
	request.Case.Expected = map[string]json.RawMessage{
		"mpp":                          json.RawMessage(`{"AEP-Authorization":"AEP compact-jws","Authorization":"Payment mpp-credential","ambiguous":false}`),
		"x402":                         json.RawMessage(`{"AEP-Authorization":"Bearer opaque-token","PAYMENT-SIGNATURE":"x402-signature","ambiguous":false}`),
		"payment_advertised_after_aep": json.RawMessage(`true`),
	}
	if result := evaluate(request); result.Status != "passed" {
		t.Fatalf("%#v", result)
	}
	request.Case.Expected["x402"] = json.RawMessage(`{"AEP-Authorization":"Bearer wrong-token","PAYMENT-SIGNATURE":"x402-signature","ambiguous":false}`)
	if evaluate(request).Status == "passed" {
		t.Fatal("invalid credential passed composition check")
	}
	request.Case.Expected["x402"] = json.RawMessage(`{"AEP-Authorization":"Bearer opaque-token","PAYMENT-SIGNATURE":"x402-signature","ambiguous":false}`)
	request.Case.Input["anonymous_status"] = json.RawMessage(`402`)
	if evaluate(request).Status == "passed" {
		t.Fatal("payment challenge before authentication passed")
	}
}

func TestServiceAmbiguityUsesValidStoredCredential(t *testing.T) {
	request := adapterRequest{Role: "service"}
	request.Vector.ID = "authorization-ambiguity"
	request.Case.Input = map[string]json.RawMessage{"cases": json.RawMessage(`["both-aep-recognized","invalid-dedicated-plus-valid-standard","duplicate-dedicated-lines","combined-dedicated-values"]`)}
	request.Case.Expected = map[string]json.RawMessage{"code": json.RawMessage(`"not_recognized"`), "disclosure": json.RawMessage(`"none"`), "fallback": json.RawMessage(`false`), "selected_credential": json.RawMessage(`null`)}
	if result := evaluate(request); result.Status != "passed" {
		t.Fatalf("%#v", result)
	}
	request.Case.Expected["code"] = json.RawMessage(`"authentication_required"`)
	if evaluate(request).Status == "passed" {
		t.Fatal("incorrect ambiguity error passed")
	}
	request.Case.Expected["code"] = json.RawMessage(`"not_recognized"`)
	request.Case.Input["cases"] = json.RawMessage(`["unknown-case"]`)
	if evaluate(request).Status == "passed" {
		t.Fatal("unknown ambiguity case passed")
	}
}

func TestAgentCommandIdempotencyUsesRequests(t *testing.T) {
	for _, key := range []string{"command-key", ""} {
		t.Run(key, func(t *testing.T) {
			encoded, err := json.Marshal(key)
			if err != nil {
				t.Fatal(err)
			}
			request := adapterRequest{Role: "agent"}
			request.Vector.ID = "command-header"
			request.Case.Input = map[string]json.RawMessage{
				"commands":        json.RawMessage(`["enroll","grant","revoke"]`),
				"idempotency_key": encoded,
			}
			response := evaluate(request)
			if (response.Status == "passed") != (key != "") {
				t.Fatalf("unexpected adapter result: %#v", response)
			}
		})
	}
}

func TestTruncateBoundsMessages(t *testing.T) {
	if got := truncate("abcdef", 3); got != "abc" {
		t.Fatalf("truncate() = %q, want %q", got, "abc")
	}
}

func TestAgentRedirectConformanceUsesHTTPRequests(t *testing.T) {
	request := adapterRequest{Role: "agent"}
	request.Vector.ID = "redirect-safety"
	request.Case.Input = map[string]json.RawMessage{
		"source":       json.RawMessage(`"https://source.example/orders/1"`),
		"same_origin":  json.RawMessage(`"https://source.example/orders/2"`),
		"cross_origin": json.RawMessage(`"https://other.example/orders/1"`),
	}
	if response := evaluate(request); response.Status != "passed" {
		t.Fatalf("%#v", response)
	}
}

func TestAgentGrantBeforeEnrollmentObservesServiceError(t *testing.T) {
	for _, code := range []string{"not_recognized", "authentication_required"} {
		t.Run(code, func(t *testing.T) {
			request := adapterRequest{Role: "agent"}
			request.Vector.ID = "grant-before-enroll-rejected"
			encoded, _ := json.Marshal(code)
			request.Case.Expected = map[string]json.RawMessage{
				"code": encoded, "status": json.RawMessage(`401`), "implicit_enrollment": json.RawMessage(`false`),
			}
			response := evaluate(request)
			if (response.Status == "passed") != (code == "not_recognized") {
				t.Fatalf("%#v", response)
			}
		})
	}
}

func TestAgentAuthenticateAssertionObservesGeneratedClaims(t *testing.T) {
	for _, operation := range []string{"authenticate", "enroll"} {
		t.Run(operation, func(t *testing.T) {
			request := adapterRequest{Role: "agent"}
			request.Vector.ID = "authenticate-assertion"
			request.Case.Input = map[string]json.RawMessage{"url": json.RawMessage(`"https://service.example/resource?query=1"`)}
			claims, err := json.Marshal(map[string]any{
				"iss": "did:web:agent.example", "sub": "did:web:agent.example", "aud": "did:web:service.example",
				"op": operation, "resource": "https://service.example/resource?query=1", "iat": 1783958400, "exp": 1783958460, "jti": "resource-assertion",
			})
			if err != nil {
				t.Fatal(err)
			}
			request.Case.Expected = map[string]json.RawMessage{"claims": claims}
			response := evaluate(request)
			if (response.Status == "passed") != (operation == "authenticate") {
				t.Fatalf("%#v", response)
			}
		})
	}
}

func TestAgentAPIKeyPresentationUsesStoredCredential(t *testing.T) {
	for _, presented := range []string{"service-api-key", "X-API-KEY"} {
		request := adapterRequest{Role: "agent"}
		request.Vector.ID = "api-key-wrong-header-rejected"
		encoded, _ := json.Marshal(presented)
		request.Case.Input = map[string]json.RawMessage{"issued_header": json.RawMessage(`"x-api-key"`), "presented_header": encoded, "api_key": json.RawMessage(`"opaque-api-key"`)}
		accepted, _ := json.Marshal(presented == "X-API-KEY")
		request.Case.Expected = map[string]json.RawMessage{"accepted": accepted}
		if response := evaluate(request); response.Status != "passed" {
			t.Fatalf("%s: %#v", presented, response)
		}
		request.Case.Expected["accepted"] = json.RawMessage(`false`)
		if presented == "X-API-KEY" && evaluate(request).Status == "passed" {
			t.Fatal("accepted an incorrect expected header result")
		}
	}
}

func TestAgentTransportExercisesInspect(t *testing.T) {
	request := adapterRequest{Role: "agent"}
	request.Vector.ID = "transport-requirements"
	request.Case.Input = map[string]json.RawMessage{
		"request_url":  json.RawMessage(`"https://api.example.com/.well-known/aep"`),
		"redirect_url": json.RawMessage(`"https://api.example.com/discovery/aep"`),
		"content_type": json.RawMessage(`"Application/AEP+JSON; charset=utf-8"`),
	}
	if response := evaluate(request); response.Status != "passed" {
		t.Fatalf("%#v", response)
	}
	request.Case.Input["content_type"] = json.RawMessage(`"text/html"`)
	if evaluate(request).Status == "passed" {
		t.Fatal("accepted an invalid Inspect media type")
	}
}

func TestAgentPaymentCompositionObservesRequests(t *testing.T) {
	request := adapterRequest{Role: "agent"}
	request.Vector.ID = "authorization-payment-composition"
	request.Case.Expected = map[string]json.RawMessage{
		"mpp":  json.RawMessage(`{"AEP-Authorization":"AEP compact-jws","Authorization":"Payment mpp-credential"}`),
		"x402": json.RawMessage(`{"AEP-Authorization":"Bearer opaque-token","PAYMENT-SIGNATURE":"x402-signature"}`),
	}
	if response := evaluate(request); response.Status != "passed" {
		t.Fatalf("%#v", response)
	}
	request.Case.Expected["x402"] = json.RawMessage(`{"AEP-Authorization":"Bearer wrong-token","PAYMENT-SIGNATURE":"x402-signature"}`)
	if evaluate(request).Status == "passed" {
		t.Fatal("accepted incorrect emitted credentials")
	}
}

func TestProtectedResourceFailureScenarios(t *testing.T) {
	request := adapterRequest{Role: "agent"}
	request.Vector.ID = "assertion-and-credential-failures"
	request.Case.Input = map[string]json.RawMessage{"cases": json.RawMessage(`["wrong_audience","expired_assertion","replayed_assertion","malformed_credential","expired_credential","unsupported_method","insufficient_scope"]`)}
	request.Case.Expected = map[string]json.RawMessage{}
	for _, failure := range []string{"wrong_audience", "expired_assertion", "replayed_assertion", "malformed_credential", "expired_credential"} {
		request.Case.Expected[failure] = json.RawMessage(`"not_recognized"`)
	}
	request.Case.Expected["unsupported_method"] = json.RawMessage(`"unsupported_authentication_method"`)
	request.Case.Expected["insufficient_scope"] = json.RawMessage(`"insufficient_scope"`)
	if response := evaluate(request); response.Status != "passed" {
		t.Fatalf("%#v", response)
	}
	request.Role = "service"
	if response := evaluate(request); response.Status != "passed" {
		t.Fatalf("%#v", response)
	}
	for name, expected := range request.Case.Expected {
		t.Run(name, func(t *testing.T) {
			request.Case.Expected[name] = json.RawMessage(`"authentication_required"`)
			if evaluate(request).Status == "passed" {
				t.Fatal("accepted an incorrect failure code")
			}
			request.Case.Expected[name] = expected
		})
	}
	request.Case.Input["cases"] = json.RawMessage(`["unknown"]`)
	request.Case.Expected["unknown"] = json.RawMessage(`"not_recognized"`)
	if evaluate(request).Status == "passed" {
		t.Fatal("accepted an unimplemented failure case")
	}
}

func TestAgentUnadvertisedMethodsUseStoredCredential(t *testing.T) {
	request := adapterRequest{Role: "agent"}
	request.Vector.ID = "unadvertised-authentication-method"
	request.Case.Input = map[string]json.RawMessage{
		"advertised_methods":      json.RawMessage(`["api-key"]`),
		"unadvertised_credential": json.RawMessage(`"oauth-bearer"`),
		"unadvertised_grant_type": json.RawMessage(`"basic"`),
	}
	if response := evaluate(request); response.Status != "passed" {
		t.Fatalf("%#v", response)
	}
	request.Case.Input["advertised_methods"] = json.RawMessage(`["oauth-bearer"]`)
	if evaluate(request).Status == "passed" {
		t.Fatal("reported an advertised credential as rejected")
	}
}

func TestAgentCarrierSafetyObservesOutgoingHeaders(t *testing.T) {
	request := adapterRequest{Role: "agent"}
	request.Vector.ID = "authorization-ambiguity"
	request.Case.Input = map[string]json.RawMessage{"cases": json.RawMessage(`["both-aep-recognized","invalid-dedicated-plus-valid-standard","duplicate-dedicated-lines","combined-dedicated-values"]`)}
	if response := evaluate(request); response.Status != "passed" {
		t.Fatalf("%#v", response)
	}
	request.Vector.ID = "authorization-field-safety"
	request.Case.Input = map[string]json.RawMessage{"field_name": json.RawMessage(`"aep-authorization"`)}
	if response := evaluate(request); response.Status != "passed" {
		t.Fatalf("%#v", response)
	}
}

func TestAgentOperationBindingObservesGeneratedAssertions(t *testing.T) {
	request := adapterRequest{Role: "agent"}
	request.Vector.ID = "operation-substitution-rejected"
	request.Case.Input = map[string]json.RawMessage{
		"operations":         json.RawMessage(`["enroll","grant","revoke","status","authenticate"]`),
		"protected_resource": json.RawMessage(`"https://api.example.com/v1/orders"`),
	}
	request.Case.Expected = map[string]json.RawMessage{"allowed": json.RawMessage(`["enroll:enroll","grant:grant","revoke:revoke","status:status","authenticate:protected-resource"]`)}
	if response := evaluate(request); response.Status != "passed" {
		t.Fatalf("%#v", response)
	}
	request.Case.Expected["allowed"] = json.RawMessage(`["enroll:enroll","grant:grant","revoke:revoke","status:status","status:protected-resource"]`)
	if evaluate(request).Status == "passed" {
		t.Fatal("accepted a substituted operation")
	}
}
