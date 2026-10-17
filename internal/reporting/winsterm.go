//go:build windows

package reporting

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// enableVirtualTerminalProcessing is the console mode flag that makes the
// Windows console host interpret ANSI SGR escape sequences (colors, cursor
// control) instead of printing them literally.
const enableVirtualTerminalProcessing = 0x0004

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

// enableColor turns on virtual-terminal processing for the stdout console
// handle so ANSI color sequences render on Windows. It returns false when
// stdout is not a real console (pipe/redirect) or the syscall fails — in
// that case callers fall back to plain ASCII output, keeping redirected
// logs clean.
func enableColor() bool {
	handle := windows.Handle(os.Stdout.Fd())
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return false
	}
	r, _, _ = procSetConsoleMode.Call(uintptr(handle), uintptr(mode|enableVirtualTerminalProcessing))
	return r != 0
}
