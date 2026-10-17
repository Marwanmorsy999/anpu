//go:build windows

package reporting

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVirtualTerminalProcessing is the console mode flag that makes the
// Windows console host interpret ANSI SGR escape sequences (colors, cursor
// control) instead of printing them literally.
const enableVirtualTerminalProcessing = 0x0004

// enableColor turns on virtual-terminal processing for the stdout console
// handle so ANSI color sequences render on Windows. It returns false when
// stdout is not a real console (pipe/redirect) or the call fails — in that
// case callers fall back to plain ASCII output, keeping redirected logs clean.
func enableColor() bool {
	handle := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	return windows.SetConsoleMode(handle, mode|enableVirtualTerminalProcessing) == nil
}
