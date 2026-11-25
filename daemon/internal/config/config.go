// Package config loads /etc/sentinel/config.json.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

type Config struct {
	Socket   string `json:"socket"`
	StateDir string `json:"state_dir"`
	AuditLog string `json:"audit_log"`
	LoginLog string `json:"login_log"`

	BruteForce struct {
		Enabled   bool     `json:"enabled"`
		Threshold int      `json:"threshold"`
		WindowMin int      `json:"window_minutes"`
		BanMin    int      `json:"ban_minutes"`
		Allowlist []string `json:"allowlist"`
	} `json:"brute_force"`
}

func Default() Config {
	var c Config
	c.Socket = "/run/sentinel/sentinel.sock"
	c.StateDir = "/var/lib/sentinel"
	c.AuditLog = "/var/log/sentinel/audit.log"
	c.LoginLog = "/usr/local/cpanel/logs/login_log"
	c.BruteForce.Enabled = true
	c.BruteForce.Threshold = 10
	c.BruteForce.WindowMin = 10
	c.BruteForce.BanMin = 60
	c.BruteForce.Allowlist = []string{"127.0.0.0/8", "::1"}
	return c
}

// Load reads path over the defaults. A missing file means defaults.
func Load(path string) (Config, error) {
	c := Default()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	bf := c.BruteForce
	if bf.Threshold < 1 || bf.WindowMin < 1 || bf.BanMin < 1 {
		return fmt.Errorf("brute_force threshold, window_minutes and ban_minutes must be at least 1")
	}
	if c.Socket == "" || c.StateDir == "" || c.AuditLog == "" {
		return fmt.Errorf("socket, state_dir and audit_log are required")
	}
	return nil
}

func (c Config) Window() time.Duration { return time.Duration(c.BruteForce.WindowMin) * time.Minute }
func (c Config) BanFor() time.Duration { return time.Duration(c.BruteForce.BanMin) * time.Minute }
