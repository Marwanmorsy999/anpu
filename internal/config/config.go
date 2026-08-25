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

// applyBool overrides dst with src if src is non-nil.
func applyBool(dst *bool, src *bool) {
	if src != nil {
		*dst = *src
	}
}

// ResolveModules computes the effective ModuleConfig for a scan given
// the profile default, the config file, and the --no-nuclei/--no-zap CLI
// flags (CLI flags win last).
func ResolveModules(profile models.Profile, f *File, noNuclei, noZAP bool) models.ModuleConfig {
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
		applyBool(&mc.Nuclei, f.Modules.Nuclei)
		applyBool(&mc.ZAP, f.Modules.ZAP)
	}
	if noNuclei {
		mc.Nuclei = false
	}
	if noZAP {
		mc.ZAP = false
	}
	return mc
}
