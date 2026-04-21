package csrf

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/portainer/portainer/api/http/security"
	"github.com/portainer/portainer/pkg/featureflags"
	httperror "github.com/portainer/portainer/pkg/libhttp/error"

	gcsrf "github.com/gorilla/csrf"
	"github.com/rs/zerolog/log"
	"github.com/urfave/negroni"
)

const csrfSkipHeader = "X-CSRF-Token-Skip"

// SkipCSRFToken signals that the X-CSRF-Token header should not be sent in the response.
// Deprecated: only meaningful when the "legacy-csrf" feature flag is enabled.
func SkipCSRFToken(w http.ResponseWriter) {
	w.Header().Set(csrfSkipHeader, "1")
}

func WithProtect(handler http.Handler, trustedOrigins []string) (http.Handler, error) {
	// DOCKER_EXTENSION=1 is set in build/docker-extension/docker-compose.yml
	isDockerDesktopExtension := false
	if val, ok := os.LookupEnv("DOCKER_EXTENSION"); ok && val == "1" {
		isDockerDesktopExtension = true
	}

	if featureflags.IsEnabled("legacy-csrf") {
		return withLegacyProtect(handler, trustedOrigins, isDockerDesktopExtension)
	}

	cop := http.NewCrossOriginProtection()
	for _, origin := range trustedOrigins {
		if err := cop.AddTrustedOrigin(origin); err != nil {
			return nil, fmt.Errorf("failed to add trusted origin %q: %w", origin, err)
		}
	}

	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Error().Err(cop.Check(r)).
			Str("request_url", r.URL.String()).
			Str("host", r.Host).
			Str("origin", r.Header.Get("Origin")).
			Str("sec_fetch_site", r.Header.Get("Sec-Fetch-Site")).
			Strs("trusted_origins", trustedOrigins).
			Msg("CSRF check failed")

		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	}))

	protected := cop.Handler(handler)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		skip, err := security.ShouldSkipCSRFCheck(r, isDockerDesktopExtension)
		if err != nil {
			httperror.WriteError(w, http.StatusForbidden, err.Error(), err)

			return
		}

		if skip {
			handler.ServeHTTP(w, r)

			return
		}

		protected.ServeHTTP(w, r)
	}), nil
}

// Deprecated: use WithProtect without the "legacy-csrf" feature flag instead.
func withLegacyProtect(handler http.Handler, trustedOrigins []string, isDockerDesktopExtension bool) (http.Handler, error) {
	handler = withLegacySendCSRFToken(handler)

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("failed to generate CSRF token: %w", err)
	}

	handler = gcsrf.Protect(
		token,
		gcsrf.Path("/"),
		gcsrf.Secure(false),
		gcsrf.TrustedOrigins(trustedOrigins),
		gcsrf.ErrorHandler(withLegacyErrorHandler(trustedOrigins)),
	)(handler)

	return withLegacySkipCSRF(handler, isDockerDesktopExtension), nil
}

// Deprecated: use WithProtect without the "legacy-csrf" feature flag instead.
func withLegacySendCSRFToken(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := negroni.NewResponseWriter(w)

		sw.Before(func(sw negroni.ResponseWriter) {
			if len(sw.Header().Get(csrfSkipHeader)) > 0 {
				sw.Header().Del(csrfSkipHeader)

				return
			}

			if statusCode := sw.Status(); statusCode >= 200 && statusCode < 300 {
				sw.Header().Set("X-CSRF-Token", gcsrf.Token(r))
			}
		})

		handler.ServeHTTP(sw, r)
	})
}

// Deprecated: use WithProtect without the "legacy-csrf" feature flag instead.
func withLegacySkipCSRF(handler http.Handler, isDockerDesktopExtension bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		skip, err := security.ShouldSkipCSRFCheck(r, isDockerDesktopExtension)
		if err != nil {
			httperror.WriteError(w, http.StatusForbidden, err.Error(), err)

			return
		}

		if skip {
			r = gcsrf.UnsafeSkipCheck(r)
		}

		handler.ServeHTTP(w, r)
	})
}

// Deprecated: use WithProtect without the "legacy-csrf" feature flag instead.
func withLegacyErrorHandler(trustedOrigins []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := gcsrf.FailureReason(r)

		if errors.Is(err, gcsrf.ErrBadOrigin) || errors.Is(err, gcsrf.ErrBadReferer) || errors.Is(err, gcsrf.ErrNoReferer) {
			log.Error().Err(err).
				Str("request_url", r.URL.String()).
				Str("host", r.Host).
				Str("x_forwarded_proto", r.Header.Get("X-Forwarded-Proto")).
				Str("forwarded", r.Header.Get("Forwarded")).
				Str("origin", r.Header.Get("Origin")).
				Str("referer", r.Header.Get("Referer")).
				Strs("trusted_origins", trustedOrigins).
				Msg("Failed to validate Origin or Referer")
		}

		http.Error(
			w,
			http.StatusText(http.StatusForbidden)+" - "+err.Error(),
			http.StatusForbidden,
		)
	})
}
