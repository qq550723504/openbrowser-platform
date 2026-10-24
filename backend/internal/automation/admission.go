package automation

import "context"

type admissionKey struct{}

func WithAdmission(ctx context.Context, check func() error) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, admissionKey{}, check)
}

// Production wires this to the same authority as Wails/HTTP. Private test
// managers retain their existing isolated fixtures; no product bypass exists.
func (m *Manager) captureAdmission(ctx context.Context) func() error {
	if ctx != nil {
		if check, ok := ctx.Value(admissionKey{}).(func() error); ok {
			return check
		}
	}
	if m.options.CaptureAdmission == nil {
		return func() error { return nil }
	}
	return m.options.CaptureAdmission()
}
