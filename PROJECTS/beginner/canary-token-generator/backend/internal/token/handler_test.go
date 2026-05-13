// ©AngelaMos | 2026
// handler_test.go

package token_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
)

type triggerGen struct {
	tokenType token.Type
	artifact  generators.Artifact
	resp      *generators.TriggerResponse
	evt       *event.Event
}

func (g *triggerGen) Type() token.Type { return g.tokenType }

func (g *triggerGen) Generate(
	_ context.Context,
	_ *token.Token,
	_ string,
) (generators.Artifact, error) {
	return g.artifact, nil
}

func (g *triggerGen) Trigger(
	_ context.Context,
	_ *token.Token,
	_ *http.Request,
) (*event.Event, *generators.TriggerResponse, error) {
	return g.evt, g.resp, nil
}

type recordingEvents struct {
	events []*event.Event
}

func (r *recordingEvents) Record(
	_ context.Context,
	_ *token.Token,
	e *event.Event,
) error {
	r.events = append(r.events, e)
	return nil
}

func quietHandlerLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newWebbugHandler(
	t *testing.T,
	gen token.Generator,
) (*token.Handler, *fakeRepo, *recordingEvents) {
	t.Helper()
	repo := newFakeRepo()
	rec := &recordingEvents{}
	svc := token.NewService(
		repo,
		token.MapRegistry{token.TypeWebbug: gen},
		token.ServiceConfig{
			BaseURL:   "https://canary.example.com",
			ManageURL: "https://canary.example.com",
		},
	)
	return token.NewHandler(svc, rec, nil, quietHandlerLogger()), repo, rec
}

func TestGetTypes_Returns7Types(t *testing.T) {
	svc := token.NewService(newFakeRepo(), token.MapRegistry{},
		token.ServiceConfig{BaseURL: "https://x.test"})
	h := token.NewHandler(svc, nil, nil, quietHandlerLogger())

	r := chi.NewRouter()
	h.RegisterAPIRoutes(r)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tokens/types", nil))

	require.Equal(t, http.StatusOK, w.Code)
	var body struct {
		Success bool                   `json:"success"`
		Data    []token.TypeDescriptor `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	require.True(t, body.Success)
	require.Len(t, body.Data, 7)
}

func TestCreateToken_HappyPath(t *testing.T) {
	gen := &triggerGen{
		tokenType: token.TypeWebbug,
		artifact: generators.Artifact{
			Kind: generators.KindURL, URL: "https://canary.example.com/c/x",
		},
	}
	h, _, _ := newWebbugHandler(t, gen)

	r := chi.NewRouter()
	h.RegisterAPIRoutes(r)

	body := strings.NewReader(`{
		"type":"webbug","memo":"m","alert_channel":"webhook",
		"webhook_url":"https://example.com/h","cf_turnstile_response":"t",
		"metadata":{}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/tokens", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code)

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Token    token.Response     `json:"token"`
			Artifact token.ArtifactJSON `json:"artifact"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.True(t, resp.Success)
	require.Equal(t, token.TypeWebbug, resp.Data.Token.Type)
	require.NotEmpty(t, resp.Data.Token.ID)
	require.Contains(t, resp.Data.Token.TriggerURL, "/c/")
	require.Contains(t, resp.Data.Token.ManageURL, "/m/")
	require.Equal(t, "url", resp.Data.Artifact.Kind)
}

func TestCreateToken_BadJSON(t *testing.T) {
	gen := &triggerGen{tokenType: token.TypeWebbug}
	h, _, _ := newWebbugHandler(t, gen)

	r := chi.NewRouter()
	h.RegisterAPIRoutes(r)

	req := httptest.NewRequest(
		http.MethodPost,
		"/tokens",
		strings.NewReader(`{not json`),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "BAD_JSON")
}

func TestCreateToken_ValidationFailure(t *testing.T) {
	gen := &triggerGen{tokenType: token.TypeWebbug}
	h, _, _ := newWebbugHandler(t, gen)

	r := chi.NewRouter()
	h.RegisterAPIRoutes(r)

	body := strings.NewReader(
		`{"type":"webbug","memo":"m","cf_turnstile_response":"t"}`,
	)
	req := httptest.NewRequest(http.MethodPost, "/tokens", body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "VALIDATION_ERROR")
}

func TestHandleTrigger_KnownTokenReturnsResponseAndRecordsEvent(t *testing.T) {
	gen := &triggerGen{
		tokenType: token.TypeWebbug,
		artifact:  generators.Artifact{Kind: generators.KindURL},
		resp: &generators.TriggerResponse{
			StatusCode:  200,
			ContentType: "image/gif",
			Body:        []byte{0x47, 0x49, 0x46, 0x38},
		},
		evt: &event.Event{SourceIP: "1.2.3.4"},
	}
	h, repo, rec := newWebbugHandler(t, gen)

	tok := &token.Token{
		ID: "abcdef012345", ManageID: "m", Type: token.TypeWebbug,
		AlertChannel: token.ChannelWebhook, Enabled: true,
		Metadata: json.RawMessage(`{}`),
	}
	require.NoError(t, repo.Insert(context.Background(), tok))

	r := chi.NewRouter()
	h.RegisterTriggerRoutes(r)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/c/abcdef012345", nil)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "image/gif", w.Header().Get("Content-Type"))
	require.Equal(t, []byte{0x47, 0x49, 0x46, 0x38}, w.Body.Bytes())
	require.Len(t, rec.events, 1)
}

func TestHandleTrigger_UnknownTokenStillReturnsArtifactShape(t *testing.T) {
	gen := &triggerGen{
		tokenType: token.TypeWebbug,
		resp: &generators.TriggerResponse{
			StatusCode:  200,
			ContentType: "image/gif",
			Body:        []byte{0x47, 0x49, 0x46},
		},
	}
	h, _, rec := newWebbugHandler(t, gen)

	r := chi.NewRouter()
	h.RegisterTriggerRoutes(r)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/c/nonexistent1", nil))

	require.Equal(t, http.StatusOK, w.Code,
		"unknown tokens still return artifact shape (defense in depth)")
	require.Empty(t, rec.events, "no event recorded for unknown token")
}

func TestHandleTrigger_DisabledTokenIsTreatedAsUnknown(t *testing.T) {
	gen := &triggerGen{
		tokenType: token.TypeWebbug,
		resp: &generators.TriggerResponse{
			StatusCode:  200,
			ContentType: "image/gif",
			Body:        []byte{0x47},
		},
		evt: &event.Event{SourceIP: "1.2.3.4"},
	}
	h, repo, rec := newWebbugHandler(t, gen)

	tok := &token.Token{
		ID: "disabled1234", ManageID: "m", Type: token.TypeWebbug,
		AlertChannel: token.ChannelWebhook, Enabled: false,
		Metadata: json.RawMessage(`{}`),
	}
	require.NoError(t, repo.Insert(context.Background(), tok))

	r := chi.NewRouter()
	h.RegisterTriggerRoutes(r)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/c/disabled1234", nil))

	require.Equal(t, http.StatusOK, w.Code)
	require.Empty(t, rec.events, "disabled token must not record events")
}

func TestHandleFingerprint_Returns204WithNoRecorder(t *testing.T) {
	gen := &triggerGen{tokenType: token.TypeWebbug}
	h, _, _ := newWebbugHandler(t, gen)

	r := chi.NewRouter()
	h.RegisterTriggerRoutes(r)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		"/c/anything/fingerprint", strings.NewReader(`{"x":1}`)))

	require.Equal(t, http.StatusNoContent, w.Code)
}

func TestArtifactToJSON_Kinds(t *testing.T) {
	cases := []struct {
		name string
		in   generators.Artifact
		want token.ArtifactJSON
	}{
		{
			"url",
			generators.Artifact{
				Kind:           generators.KindURL,
				URL:            "u",
				DestinationURL: "d",
			},
			token.ArtifactJSON{Kind: "url", URL: "u", DestinationURL: "d"},
		},
		{
			"file",
			generators.Artifact{
				Kind:        generators.KindFile,
				Filename:    "f.docx",
				ContentType: "x",
				Content:     []byte("hi"),
			},
			token.ArtifactJSON{
				Kind:        "file",
				Filename:    "f.docx",
				ContentType: "x",
				ContentB64:  "aGk=",
			},
		},
		{
			"text",
			generators.Artifact{
				Kind:        generators.KindText,
				Filename:    ".env",
				ContentType: "text/plain",
				Content:     []byte("KEY=v"),
			},
			token.ArtifactJSON{
				Kind:        "text",
				Filename:    ".env",
				ContentType: "text/plain",
				Content:     "KEY=v",
			},
		},
		{
			"conn",
			generators.Artifact{
				Kind:             generators.KindConnectionString,
				ConnectionString: "mysql://x",
			},
			token.ArtifactJSON{
				Kind:             "connection_string",
				ConnectionString: "mysql://x",
			},
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, exposeArtifactToJSON(c.in))
		})
	}
}

func exposeArtifactToJSON(a generators.Artifact) token.ArtifactJSON {
	gen := &triggerGen{tokenType: token.TypeWebbug, artifact: a}
	repo := newFakeRepo()
	svc := token.NewService(repo, token.MapRegistry{token.TypeWebbug: gen},
		token.ServiceConfig{BaseURL: "https://x"})
	h := token.NewHandler(svc, nil, nil, quietHandlerLogger())

	r := chi.NewRouter()
	h.RegisterAPIRoutes(r)

	body := strings.NewReader(
		`{"type":"webbug","alert_channel":"webhook","webhook_url":"https://x/h","cf_turnstile_response":"t","metadata":{}}`,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/tokens", body))

	var resp struct {
		Data struct {
			Artifact token.ArtifactJSON `json:"artifact"`
		} `json:"data"`
	}
	if jsonErr := json.NewDecoder(w.Body).Decode(&resp); jsonErr != nil {
		panic(jsonErr)
	}
	return resp.Data.Artifact
}
