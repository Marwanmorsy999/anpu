// Package config loads and merges ANPU's YAML configuration file with
// CLI flags. CLI flags always take precedence over file values.
package config

import (
	"fmt"
	"os"

	"github.com/anpu-project/anpu/pkg/models"
	"gopkg.in/yaml.v3"
)

// TargetConfig mirrors the `target:` section of the YAML config.
type TargetConfig struct {
	URL string `yaml:"url"`
}

// AuthFileConfig mirrors the `auth:` section of the YAML config.
// Credentials supplied here are merged with CLI flags; CLI flags win.
//
// NEVER commit real credentials.  Use environment variable references
// or pass credentials on the command line for sensitive values.
type AuthFileConfig struct {
	Method  string   `yaml:"method"`
	Token   string   `yaml:"token"`
	Cookies []string `yaml:"cookies"`
	Headers []string `yaml:"headers"`
	Role    string   `yaml:"role"`
}

// ScanFileConfig mirrors the `scan:` section.
type ScanFileConfig struct {
	Profile string `yaml:"profile"`
}

// ModulesFileConfig mirrors the `modules:` section. Pointers distinguish
// "unset" (use profile default) from an explicit true/false.
type ModulesFileConfig struct {
	Recon      *bool `yaml:"recon"`
	Technology *bool `yaml:"technology"`
	TLS        *bool `yaml:"tls"`
	Headers    *bool `yaml:"headers"`
	Cookies    *bool `yaml:"cookies"`
	Endpoints  *bool `yaml:"endpoints"`
	Subdomains *bool `yaml:"subdomains"`
	PortScan   *bool `yaml:"portscan"`
	Dirs       *bool `yaml:"dirs"`
	Secrets    *bool `yaml:"secrets"`
	CORS       *bool `yaml:"cors"`
	Methods    *bool `yaml:"methods"`
	CSRF       *bool `yaml:"csrf"`
	Deps       *bool `yaml:"deps"`
	Active     *bool `yaml:"active"`
	Nuclei     *bool `yaml:"nuclei"`
	ZAP        *bool `yaml:"zap"`
}

// ReportFileConfig mirrors the `report:` section.
type ReportFileConfig struct {
	HTML  *bool `yaml:"html"`
	JSON  *bool `yaml:"json"`
	SARIF *bool `yaml:"sarif"`
}

// File is the root of anpu's YAML configuration file.
type File struct {
	Target  TargetConfig      `yaml:"target"`
	Scan    ScanFileConfig    `yaml:"scan"`
	Modules ModulesFileConfig `yaml:"modules"`
	Report  ReportFileConfig  `yaml:"report"`
	Auth    AuthFileConfig    `yaml:"auth"`
}

// Load reads and parses a YAML config file at path. It is not an error
// for the file to not exist — callers should treat that as "use
// defaults / CLI flags only".
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &File{}, nil
		}
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}
	return &f, nil
}

// ResolveAuth returns the effective AuthContext for a scan, merging YAML
// config with CLI flag values.  CLI flags always win over file values.
// An empty AuthContext (all-zero) is returned when neither source
// provides credentials.
//
// The caller is responsible for calling Validate() on the result.
func ResolveAuth(f *File, cliToken string, cliCookies, cliHeaders []string, cliRole string) (models.AuthContext, error) {
	// Start from file values.
	token := cliToken
	cookies := cliCookies
	hdrs := cliHeaders
	role := cliRole

	if f != nil && f.Auth.Method != "" {
		// Only pull from file if CLI didn't supply a credential.
		if token == "" && len(cookies) == 0 && len(hdrs) == 0 {
			token = f.Auth.Token
			cookies = f.Auth.Cookies
			hdrs = f.Auth.Headers
		}
		if role == "" {
			role = f.Auth.Role
		}
	}

	// Delegate to the auth package constructor for validation logic.
	// We call it directly here to keep config independent of auth, but
	// the logic is: pick the first non-empty credential type, validate,
	// return.
	active := 0
	if token != "" {
		active++
	}
	if len(cookies) > 0 {
		active++
	}
	if len(hdrs) > 0 {
		active++
	}
	if active > 1 {
		return models.AuthContext{}, fmt.Errorf(
			"at most one auth method may be active (bearer_token, cookies, or headers)",
		)
	}

	ctx := models.AuthContext{}
	switch {
	case token != "":
		ctx.Method = models.AuthMethodBearer
		ctx.BearerToken = token
		if role == "" {
			role = "user"
		}
	case len(cookies) > 0:
		ctx.Method = models.AuthMethodCookie
		ctx.Cookies = cookies
		if role == "" {
			role = "user"
		}
	case len(hdrs) > 0:
		ctx.Method = models.AuthMethodHeader
		ctx.Headers = hdrs
		if role == "" {
			role = "user"
		}
	default:
		ctx.Method = models.AuthMethodNone
		if role == "" {
			role = "anonymous"
		}
	}
	ctx.Role = models.AuthRole(role)

	if err := ctx.Validate(); err != nil {
		return models.AuthContext{}, err
	}
	return ctx, nil
}

// applyBool overrides dst with src if src is non-nil.
func applyBool(dst *bool, src *bool) {
	if src != nil {
		*dst = *src
	}
}

// ResolveModules computes the effective ModuleConfig for a scan given
// the profile default, the config file, and the --no-nuclei/--no-zap CLI
// flags (CLI flags win last).
func ResolveModules(profile models.Profile, f *File, noNuclei, noZAP, noActive, noCSRF, noDeps bool) models.ModuleConfig {
	mc := models.DefaultModuleConfig(profile)
	if f != nil {
		applyBool(&mc.Recon, f.Modules.Recon)
		applyBool(&mc.Technology, f.Modules.Technology)
		applyBool(&mc.TLS, f.Modules.TLS)
		applyBool(&mc.Headers, f.Modules.Headers)
		applyBool(&mc.Cookies, f.Modules.Cookies)
		applyBool(&mc.Endpoints, f.Modules.Endpoints)
		applyBool(&mc.Subdomains, f.Modules.Subdomains)
		applyBool(&mc.PortScan, f.Modules.PortScan)
		applyBool(&mc.Dirs, f.Modules.Dirs)
		applyBool(&mc.Secrets, f.Modules.Secrets)
		applyBool(&mc.CORS, f.Modules.CORS)
		applyBool(&mc.Methods, f.Modules.Methods)
		applyBool(&mc.CSRF, f.Modules.CSRF)
		applyBool(&mc.Deps, f.Modules.Deps)
		applyBool(&mc.Active, f.Modules.Active)
		applyBool(&mc.Nuclei, f.Modules.Nuclei)
		applyBool(&mc.ZAP, f.Modules.ZAP)
	}
	if noActive {
		mc.Active = false
	}
	if noNuclei {
		mc.Nuclei = false
	}
	if noZAP {
		mc.ZAP = false
	}
	if noCSRF {
		mc.CSRF = false
	}
	if noDeps {
		mc.Deps = false
	}
	return mc
}
