// ©AngelaMos | 2026
// generator.go

package generators

import (
	"context"
	"net/http"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
)

type ArtifactKind string

const (
	KindURL              ArtifactKind = "url"
	KindFile             ArtifactKind = "file"
	KindText             ArtifactKind = "text"
	KindConnectionString ArtifactKind = "connection_string"
)

type Artifact struct {
	Kind             ArtifactKind
	URL              string
	Filename         string
	Content          []byte
	ContentType      string
	ConnectionString string
	DestinationURL   string
}

type TriggerResponse struct {
	StatusCode   int
	ContentType  string
	Body         []byte
	RedirectURL  string
	ExtraHeaders map[string]string
}

type Generator interface {
	Type() token.Type
	Generate(ctx context.Context, t *token.Token, baseURL string) (Artifact, error)
	Trigger(ctx context.Context, t *token.Token, r *http.Request) (*event.Event, *TriggerResponse, error)
}
