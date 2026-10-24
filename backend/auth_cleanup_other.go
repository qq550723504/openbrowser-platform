//go:build !windows

package backend

// Until equivalent OS identity/endpoint proof is implemented, cleanup fails
// closed. The browser's native window close and app-only exit remain available.
func ownedProcessCreation(int) (string, error)    { return "", errOwnedCleanupUnknown }
func ownedProcessEndpoint(int, string, int) error { return errOwnedCleanupUnknown }
