package models

import (
	"reflect"
	"strings"
)

// modules_byname.go — reflection helpers over the `wrapper` struct tags
// on ModuleConfig (Wave 2 free-binary wrappers, items 51-134).
//
// The 84 wrappers share one toggle/YAML/default mechanism instead of
// 84 switch cases: a name is normalized (lowercase alphanumerics) and
// matched against each field's `wrapper` tag. Core modules keep their
// explicit switch in cmd/anpu/scan.go; these helpers are the fallback.

// wrapperSafeOn lists wrappers enabled even on the safe profile (local,
// passive, zero target traffic).
var wrapperSafeOn = map[string]bool{"searchsploit": true}

// wrapperUltraOnly lists wrappers enabled only on ultra (noisy fuzzers,
// port scanners, screenshots, adversarial-gated tools).
var wrapperUltraOnly = map[string]bool{
	"ffuf": true, "gobuster": true, "feroxbuster": true, "dirsearch": true,
	"wfuzz": true, "sqlmap": true, "ghauri": true, "nikto": true,
	"commix": true, "tplmap": true, "sstimap": true, "ssrfmap": true,
	"nosqlmap": true, "smuggler": true, "dotdotpwn": true,
	"git-dumper": true, "gitjacker": true, "nmap": true, "masscan": true,
	"rustscan": true, "gowitness": true, "aquatone": true, "mobsf": true,
	"graphqlmap": true,
}

// NormalizeModuleName lowercases and strips non-alphanumerics so
// "osv-scanner", "osv_scanner", and "OsvScanner" all match.
func NormalizeModuleName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// WrapperNames returns every registry name from `wrapper` tags, sorted
// by field order.
func WrapperNames() []string {
	var out []string
	t := reflect.TypeOf(ModuleConfig{})
	for i := 0; i < t.NumField(); i++ {
		if tag := t.Field(i).Tag.Get("wrapper"); tag != "" {
			out = append(out, tag)
		}
	}
	return out
}

// wrapperField returns the struct field index for a registry name.
func wrapperField(name string) (int, bool) {
	want := NormalizeModuleName(name)
	t := reflect.TypeOf(ModuleConfig{})
	for i := 0; i < t.NumField(); i++ {
		if tag := t.Field(i).Tag.Get("wrapper"); tag != "" && NormalizeModuleName(tag) == want {
			return i, true
		}
	}
	return 0, false
}

// GetModuleByName reads a wrapper toggle; ok is false for unknown names.
func GetModuleByName(mc ModuleConfig, name string) (on, ok bool) {
	i, found := wrapperField(name)
	if !found {
		return false, false
	}
	return reflect.ValueOf(mc).Field(i).Bool(), true
}

// SetModuleByName writes a wrapper toggle; false means unknown name.
func SetModuleByName(mc *ModuleConfig, name string, on bool) bool {
	i, found := wrapperField(name)
	if !found {
		return false
	}
	reflect.ValueOf(mc).Elem().Field(i).SetBool(on)
	return true
}

// applyWrapperDefaults sets wrapper toggles for a profile: safe gets
// only local/passive wrappers, advanced adds polite-active, ultra adds
// everything (adversarial-gated tools still need --adversarial at run).
func applyWrapperDefaults(mc *ModuleConfig, p Profile) {
	t := reflect.TypeOf(ModuleConfig{})
	v := reflect.ValueOf(mc).Elem()
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("wrapper")
		if tag == "" {
			continue
		}
		on := false
		switch p {
		case ProfileSafe:
			on = wrapperSafeOn[tag]
		case ProfileAdvanced:
			on = !wrapperUltraOnly[tag]
		case ProfileUltra:
			on = true
		}
		v.Field(i).SetBool(on)
	}
}
