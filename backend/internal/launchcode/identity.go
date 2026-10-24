package launchcode

import (
	"context"
	"errors"
	"net/http"
	"time"
)

type identityAuthority interface {
	Check(uint64) error
	CheckAPI() (uint64, error)
}

// SetIdentityAuthority supplies the desktop's authority, never a renderer
// identity or an API-key-derived login. Configure before Start.
func (s *LaunchServer) SetIdentityAuthority(identity identityAuthority, factory func(uint64) (BrowserStarter, error)) {
	s.identity, s.scopedStarter = identity, factory
}

func (s *LaunchServer) identityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}
		if s.identity == nil {
			writeJSON(w, 401, map[string]any{"error": "authentication_required"})
			return
		}
		generation, err := s.identity.CheckAPI()
		if err != nil {
			writeJSON(w, 401, map[string]any{"error": "authentication_required"})
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		// Revokes active HTTP/CDP upgrades, without closing the browser itself.
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					current, err := s.identity.CheckAPI()
					if err != nil || current != generation || s.identity.Check(generation) != nil {
						cancel()
						return
					}
				}
			}
		}()
		operation := func() {
			current, err := s.identity.CheckAPI()
			if ctx.Err() != nil || err != nil || current != generation || s.identity.Check(generation) != nil {
				writeJSON(w, 401, map[string]any{"error": "authentication_required"})
				return
			}
			if s.scopedStarter == nil {
				writeJSON(w, 401, map[string]any{"error": "authentication_required"})
				return
			}
			starter, err := s.scopedStarter(generation)
			if err != nil {
				writeJSON(w, 401, map[string]any{"error": "authentication_required"})
				return
			}
			check := func() error {
				current, err := s.identity.CheckAPI()
				if err != nil || current != generation {
					return errRequestRevoked
				}
				return s.identity.Check(generation)
			}
			requestServer := &LaunchServer{launchServerState: s.launchServerState, starter: starter, admission: check}
			requestServer.apiAuthMiddleware(requestServer.buildMux()).ServeHTTP(w, r.WithContext(ctx))
		}
		operation()
	})
}

func (s *LaunchServer) checkAdmission() error {
	if s.admission != nil {
		return s.admission()
	}
	return nil
}

var errRequestRevoked = errors.New("authentication_required")
