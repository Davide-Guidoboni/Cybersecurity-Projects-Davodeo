// ©AngelaMos | 2026
// handler.go

package token

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/middleware"
)

const (
	urlParamTokenID = "id"

	headerContentType = "Content-Type"
	headerLocation    = "Location"
	contentTypeJSON   = "application/json"

	errorCodeValidation     = "VALIDATION_ERROR"
	errorCodeBadJSON        = "BAD_JSON"
	errorCodeInternalError  = "INTERNAL_ERROR"
	errorCodeUnknownType    = "UNKNOWN_TYPE"
	errorCodeGenerateFailed = "GENERATE_FAILED"

	respMessageValidation     = "request validation failed"
	respMessageBadJSON        = "invalid JSON body"
	respMessageInternalError  = "internal server error"
	respMessageGenerateFailed = "artifact generation failed"
	respMessageUnknownType    = "unknown token type"

	kubeconfigPathPrefix = "/k/"

	createTokenBodyMaxBytes = 64 * 1024
	fingerprintBodyMaxBytes = 64 * 1024
)

type EventRecorder interface {
	Record(ctx context.Context, t *Token, evt *event.Event) error
}

type FingerprintRecorder interface {
	AttachFingerprint(
		ctx context.Context,
		tokenID, sourceIP string,
		fingerprint json.RawMessage,
	) error
}

type Handler struct {
	svc                 *Service
	events              EventRecorder
	fingerprintRecorder FingerprintRecorder
	logger              *slog.Logger
}

func NewHandler(
	svc *Service,
	events EventRecorder,
	fingerprint FingerprintRecorder,
	logger *slog.Logger,
) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		svc:                 svc,
		events:              events,
		fingerprintRecorder: fingerprint,
		logger:              logger,
	}
}

func (h *Handler) RegisterAPIRoutes(r chi.Router) {
	r.Get("/tokens/types", h.GetTypes)
	r.Post("/tokens", h.CreateToken)
}

func (h *Handler) RegisterTriggerRoutes(r chi.Router) {
	r.Get("/c/{"+urlParamTokenID+"}", h.HandleTrigger)
	r.Post("/c/{"+urlParamTokenID+"}/fingerprint", h.HandleFingerprint)
	r.HandleFunc("/k/{"+urlParamTokenID+"}", h.HandleTrigger)
	r.HandleFunc("/k/{"+urlParamTokenID+"}/*", h.HandleTrigger)
}

func (h *Handler) GetTypes(w http.ResponseWriter, _ *http.Request) {
	h.writeJSON(w, http.StatusOK, envelopeData(TypeDescriptors()))
}

func (h *Handler) CreateToken(w http.ResponseWriter, r *http.Request) {
	limited := http.MaxBytesReader(w, r.Body, createTokenBodyMaxBytes)
	var req CreateRequest
	if err := json.NewDecoder(limited).Decode(&req); err != nil {
		h.writeJSON(w, http.StatusBadRequest, envelopeError(
			errorCodeBadJSON, respMessageBadJSON,
		))
		return
	}

	fp := middleware.ExtractFingerprint(r)
	ip := middleware.RealIP(r)

	tok, art, err := h.svc.Create(r.Context(), req, fp, ip)
	if err != nil {
		h.writeCreateError(w, r, err)
		return
	}

	resp := tok.ToResponse(
		h.svc.TriggerURL(tok.ID),
		h.svc.ManageURL(tok.ManageID),
	)
	h.writeJSON(w, http.StatusCreated, envelopeData(map[string]any{
		"token":    resp,
		"artifact": artifactToJSON(art),
	}))
}

func (h *Handler) HandleTrigger(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, urlParamTokenID)
	if id == "" {
		http.NotFound(w, r)
		return
	}

	tok, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		h.logger.WarnContext(r.Context(), "trigger lookup failed",
			"token_id", id, "error", err)
	}
	if tok != nil && !tok.Enabled {
		tok = nil
	}

	gen, ok := h.resolveGenerator(tok, r)
	if !ok {
		http.NotFound(w, r)
		return
	}

	evt, resp, gErr := gen.Trigger(r.Context(), tok, r)
	if gErr != nil {
		h.logger.WarnContext(r.Context(), "trigger generator failed",
			"error", gErr, "token_id", id)
		http.Error(w, respMessageInternalError, http.StatusInternalServerError)
		return
	}
	if resp == nil {
		http.NotFound(w, r)
		return
	}

	if tok != nil && evt != nil && h.events != nil {
		if recErr := h.events.Record(r.Context(), tok, evt); recErr != nil {
			h.logger.WarnContext(r.Context(), "record event failed",
				"error", recErr, "token_id", id)
		}
	}

	h.writeTriggerResponse(w, r, resp)
}

func (h *Handler) HandleFingerprint(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, urlParamTokenID)
	if id == "" || h.fingerprintRecorder == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	limited := http.MaxBytesReader(w, r.Body, fingerprintBodyMaxBytes)
	var raw json.RawMessage
	if err := json.NewDecoder(limited).Decode(&raw); err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if recErr := h.fingerprintRecorder.AttachFingerprint(
		r.Context(),
		id,
		middleware.RealIP(r),
		raw,
	); recErr != nil {
		h.logger.WarnContext(r.Context(), "attach fingerprint failed",
			"token_id", id, "error", recErr)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) resolveGenerator(
	tok *Token,
	r *http.Request,
) (Generator, bool) {
	if tok != nil {
		return h.svc.Generator(tok.Type)
	}
	if strings.HasPrefix(r.URL.Path, kubeconfigPathPrefix) {
		return h.svc.Generator(TypeKubeconfig)
	}
	return h.svc.Generator(TypeWebbug)
}

func (h *Handler) writeCreateError(
	w http.ResponseWriter,
	r *http.Request,
	err error,
) {
	switch {
	case errors.Is(err, ErrUnknownGeneratorType):
		h.writeJSON(w, http.StatusBadRequest, envelopeError(
			errorCodeUnknownType, respMessageUnknownType,
		))
	case errors.Is(err, ErrInvalidDestinationURL),
		errors.Is(err, ErrInvalidIncludeKeys):
		h.writeJSON(w, http.StatusBadRequest, envelopeError(
			errorCodeValidation, err.Error(),
		))
	case errors.Is(err, ErrGenerateFailed):
		h.logger.ErrorContext(r.Context(), "create token: generator",
			"error", err)
		h.writeJSON(w, http.StatusInternalServerError, envelopeError(
			errorCodeGenerateFailed, respMessageGenerateFailed,
		))
	case strings.Contains(err.Error(), "validate request"):
		h.writeJSON(w, http.StatusBadRequest, envelopeError(
			errorCodeValidation, respMessageValidation,
		))
	default:
		h.logger.ErrorContext(r.Context(), "create token", "error", err)
		h.writeJSON(w, http.StatusInternalServerError, envelopeError(
			errorCodeInternalError, respMessageInternalError,
		))
	}
}

func (h *Handler) writeJSON(
	w http.ResponseWriter,
	status int,
	body any,
) {
	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		h.logger.Warn("write json response", "error", err)
	}
}

func (h *Handler) writeTriggerResponse(
	w http.ResponseWriter,
	r *http.Request,
	resp *TriggerResponse,
) {
	for k, v := range resp.ExtraHeaders {
		w.Header().Set(k, v)
	}
	if resp.ContentType != "" {
		w.Header().Set(headerContentType, resp.ContentType)
	}
	if resp.RedirectURL != "" {
		w.Header().Set(headerLocation, resp.RedirectURL)
		w.WriteHeader(resp.StatusCode)
		return
	}
	w.WriteHeader(resp.StatusCode)
	if len(resp.Body) > 0 {
		if _, err := w.Write(resp.Body); err != nil {
			h.logger.WarnContext(r.Context(), "write trigger body",
				"error", err)
		}
	}
}

func envelopeData(data any) map[string]any {
	return map[string]any{"success": true, "data": data}
}

func envelopeError(code, message string) map[string]any {
	return map[string]any{
		"success": false,
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}
}

type ArtifactJSON struct {
	Kind             string `json:"kind"`
	URL              string `json:"url,omitempty"`
	DestinationURL   string `json:"destination_url,omitempty"`
	Filename         string `json:"filename,omitempty"`
	ContentType      string `json:"content_type,omitempty"`
	ContentB64       string `json:"content_b64,omitempty"`
	Content          string `json:"content,omitempty"`
	ConnectionString string `json:"connection_string,omitempty"`
}

func artifactToJSON(a Artifact) ArtifactJSON {
	out := ArtifactJSON{Kind: string(a.Kind)}
	switch a.Kind {
	case KindURL:
		out.URL = a.URL
		out.DestinationURL = a.DestinationURL
	case KindFile:
		out.Filename = a.Filename
		out.ContentType = a.ContentType
		out.ContentB64 = base64.StdEncoding.EncodeToString(a.Content)
	case KindText:
		out.Filename = a.Filename
		out.ContentType = a.ContentType
		out.Content = string(a.Content)
	case KindConnectionString:
		out.ConnectionString = a.ConnectionString
	}
	return out
}
