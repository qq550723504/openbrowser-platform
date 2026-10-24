package desktopauth

import (
	"errors"
	"testing"
)

func TestAPIGrantIsExplicitAndNeverAdoptsNextSession(t *testing.T) {
	p := newIssuer(t)
	m := p.manager(t)
	if _, err := m.CheckAPI(); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("signed-out API admitted")
	}
	login(t, p, m)
	first := m.Status().Generation
	if _, err := m.CheckAPI(); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("login implicitly granted API")
	}
	if err := m.GrantAPI(first, true); err != nil {
		t.Fatal(err)
	}
	if g, err := m.CheckAPI(); err != nil || g != first {
		t.Fatal("explicit grant unavailable")
	}
	if _, err := m.SignOut(first); err != nil {
		t.Fatal(err)
	}
	login(t, p, m)
	if err := m.Check(first); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("old generation adopted next login")
	}
	if _, err := m.CheckAPI(); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("API grant adopted next login")
	}
	if err := m.GrantAPI(m.Status().Generation, true); err != nil {
		t.Fatal(err)
	}
	p.clock.advance(2 * 60 * 60 * 1e9)
	if _, err := m.CheckAPI(); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("expired grant admitted")
	}
}
