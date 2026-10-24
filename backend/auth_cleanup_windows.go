//go:build windows

package backend

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/windows"
	"strconv"
)

func ownedProcessCreation(pid int) (string, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return "", err
	}
	if exit.HighDateTime != 0 || exit.LowDateTime != 0 {
		return "", errOwnedCleanupUnknown
	}
	return fmt.Sprintf("%08x%08x", creation.HighDateTime, creation.LowDateTime), nil
}

func ownedProcessEndpoint(pid int, userDataDir string, port int) error {
	processes, err := findBrowserUserDataProcesses(userDataDir)
	if err != nil {
		return errOwnedCleanupUnknown
	}
	found := false
	for _, p := range processes {
		if p.PID == pid && p.DebugPort == port {
			found = true
		}
	}
	if !found {
		return errOwnedCleanupUnknown
	}
	// Native helper hides its PowerShell window. Only a boolean proof leaves the
	// process; command lines and unrelated process details are never returned.
	output, err := runPowerShellJSON(`param([int]$BrowserPid,[int]$DebugPort)
$ErrorActionPreference='Stop'
$owners=@(Get-NetTCPConnection -State Listen -LocalPort $DebugPort | Where-Object { $_.LocalAddress -eq '127.0.0.1' -and $_.OwningProcess -eq $BrowserPid })
($owners.Count -eq 1) | ConvertTo-Json -Compress
`, "-BrowserPid", strconv.Itoa(pid), "-DebugPort", strconv.Itoa(port))
	if err != nil || !bytes.Equal(bytes.TrimSpace(output), []byte("true")) {
		return errOwnedCleanupUnknown
	}
	return nil
}
