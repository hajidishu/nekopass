package ddns

import "testing"

func TestConfigValidation(t *testing.T) {
	valid := DefaultConfig()
	valid.Enabled = true
	valid.RecordName = " Node.Example.COM. "
	valid.Token = "fixture-token"
	if err := valid.Normalize(); err != nil || valid.RecordName != "node.example.com" {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.Token = "" }, func(c *Config) { c.Token = "x\ny" }, func(c *Config) { c.Provider = "unknown" },
		func(c *Config) { c.RecordName = "*.example.com" }, func(c *Config) { c.RecordName = "https://example.com" },
		func(c *Config) { c.RecordName = "127.0.0.1" }, func(c *Config) { c.IPv4 = false; c.IPv6 = false },
		func(c *Config) { c.IntervalSeconds = 1 }, func(c *Config) { c.TTL = 2 }, func(c *Config) { c.ZoneID = "invalid" },
		func(c *Config) { c.IPv4URL = "http://example.com" }, func(c *Config) { c.IPv4URL = "https://user:secret@example.com" },
	} {
		c := valid
		change(&c)
		if c.Normalize() == nil {
			t.Fatal("invalid config accepted")
		}
	}
	disabled := DefaultConfig()
	if disabled.Normalize() != nil {
		t.Fatal("disabled initial config rejected")
	}
}
