package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	aep "github.com/aep-foundation/aep-go"
	"github.com/aep-foundation/aep-go/agent"
	_ "github.com/aep-foundation/aep-go/platform"
	"github.com/aep-foundation/aep-go/service"
)

func main() {
	var _ agent.IdentityProvider = (*agent.PlatformIdentityProvider)(nil)
	_ = agent.NewPlatformIdentityProvider
	var _ http.Handler = (*service.HTTPHandler)(nil)
	_ = service.NewHTTPHandler
	_ = service.NewProtectedResourceMiddleware
	_, _ = service.PrincipalFromContext(context.Background())
	_, err := service.StoredOAuthBearerGrantType(service.StoredCredentialGrantTypeOptions[aep.OAuthBearerGrantResponse]{
		Issue: func(context.Context, aep.GrantRequest, service.GrantContext) (aep.OAuthBearerGrantResponse, error) {
			return aep.OAuthBearerGrantResponse{
				AccessToken: "token", CredentialID: "credential", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), TokenType: "Bearer",
			}, nil
		},
		Store: service.NewMemoryServiceCredentialStore(),
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(aep.Version)
}
