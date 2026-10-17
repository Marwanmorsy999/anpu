//go:build !windows

package reporting

// enableColor is a no-op on Unix: the terminal interprets ANSI SGR
// sequences natively whenever stdout is a TTY. Reports stay color-capable
// and SupportsColor gates on IsTerminal()/NO_COLOR as before.
func enableColor() bool { return true }
