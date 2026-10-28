package quicpadding

import (
	pb "github.com/nekopass/nekopass/internal/protocol"
	"testing"
)

func TestOptionalConfigAndValidation(t *testing.T) {
	if c, err := ForConnection(nil); c != nil || err != nil {
		t.Fatal(c, err)
	}
	v := Config{Enabled: true}
	if err := v.Normalize(); err != nil {
		t.Fatal(err)
	}
	c, err := ForConnection(v.Proto(true))
	if err != nil || c.MaxPadding != 1400 || c.BurstBytes != 8192 {
		t.Fatal(c, err)
	}
	if c, err = ForConnection(v.Proto(false)); c != nil || err != nil {
		t.Fatal("activated outside HTTP/3", c, err)
	}
	if _, err := ForConnection(&pb.QUICPaddingConfig{Enabled: true, MaxPadding: -1}); err == nil {
		t.Fatal("negative limit accepted")
	}
}
