package desktopauth

// Check admits one new operation against an immutable session generation. It
// never holds the identity mutex while application code, I/O or dialogs run.
// An admitted write retains its original result even if logout races completion.
func (m *Manager) Check(generation uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requireIdentityLocked(generation)
}

// Login opens the system browser in trusted Go code. The authorization URL,
// verifier and tokens are never renderer DTOs.
func (m *Manager) Login(generation uint64, open func(string) error) (Status, error) {
	attempt, err := m.begin(generation)
	if err != nil {
		return m.Status(), err
	}
	if err = open(attempt.url); err != nil {
		_, _ = m.cancelAttempt(attempt.generation)
		return m.Status(), ErrLogin
	}
	return m.Status(), nil
}

func (m *Manager) Cancel(generation uint64) (Status, error) {
	return m.cancelAttempt(generation)
}

func (m *Manager) SignOut(generation uint64) (Status, error) {
	return m.logoutExpected(generation)
}

// GrantAPI is an explicit, in-memory grant by this signed-in desktop session.
// An API key alone is insufficient; grants never transfer to another generation.
func (m *Manager) GrantAPI(generation uint64, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireIdentityLocked(generation); err != nil {
		return err
	}
	m.apiGrantGeneration, m.apiGranted = generation, enabled
	return nil
}

func (m *Manager) CheckAPI() (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.apiGranted || m.requireIdentityLocked(m.apiGrantGeneration) != nil {
		return 0, ErrUnauthenticated
	}
	return m.apiGrantGeneration, nil
}
