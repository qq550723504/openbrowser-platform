package backend

import wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"

// Native functions remain unchanged; private seams let offline tests hold an
// actual business call at the dialog boundary without starting a GUI.
var openNativeFileDialog = wailsruntime.OpenFileDialog
var openNativeDirectoryDialog = wailsruntime.OpenDirectoryDialog
var saveNativeFileDialog = wailsruntime.SaveFileDialog
