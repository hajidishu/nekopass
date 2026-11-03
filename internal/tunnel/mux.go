package tunnel

import (
	"bytes"
	"encoding/json"
	"errors"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"io"
)

// MuxConfig belongs to transport, independently of the selected security.
type MuxConfig struct {
	Enabled            bool `json:"enabled"`
	MaxConnections     int  `json:"max_connections"`
	MaxStreams         int  `json:"max_streams"`
	IdleTimeoutSeconds int  `json:"idle_timeout_seconds"`
}

func DefaultMux() MuxConfig { return MuxConfig{MaxStreams: 128, IdleTimeoutSeconds: 60} }

func (c *MuxConfig) UnmarshalJSON(data []byte) error {
	type fields MuxConfig
	v := fields(DefaultMux())
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("invalid Mux configuration")
	}
	*c = MuxConfig(v)
	return nil
}
func (c MuxConfig) Validate() error {
	if c.MaxConnections < 0 || c.MaxConnections > 1024 || c.MaxStreams < 1 || c.MaxStreams > 4096 || c.IdleTimeoutSeconds < 10 || c.IdleTimeoutSeconds > 3600 {
		return errors.New("Mux configuration out of range")
	}
	return nil
}
func (c MuxConfig) Proto() *pb.MuxConfig {
	return &pb.MuxConfig{Enabled: c.Enabled, MaxConnections: int32(c.MaxConnections), MaxStreams: int32(c.MaxStreams), IdleTimeoutSeconds: int32(c.IdleTimeoutSeconds)}
}
func MuxSettings(c *pb.MuxConfig) MuxConfig {
	v := DefaultMux()
	if c == nil {
		return v
	}
	v.Enabled = c.Enabled
	v.MaxConnections = int(c.MaxConnections)
	if c.MaxStreams != 0 {
		v.MaxStreams = int(c.MaxStreams)
	}
	if c.IdleTimeoutSeconds != 0 {
		v.IdleTimeoutSeconds = int(c.IdleTimeoutSeconds)
	}
	return v
}
func MuxSupported(mode string) bool { return Raw(mode) || UDP(mode) }
