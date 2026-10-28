package quicpadding

import (
	"errors"

	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/quic-go/quic-go"
)

// Config is independent of the stream framing used by raw TCP + TLS.
type Config struct {
	Enabled        bool `json:"enabled"`
	MaxPadding     int  `json:"max_padding"`
	BurstBytes     int  `json:"burst_bytes"`
	BytesPerSecond int  `json:"bytes_per_second"`
}

func Defaults() Config {
	return Config{MaxPadding: 1400, BurstBytes: 8192, BytesPerSecond: 8192}
}

func (c *Config) Normalize() error {
	d := Defaults()
	if c.MaxPadding == 0 {
		c.MaxPadding = d.MaxPadding
	}
	if c.BurstBytes == 0 {
		c.BurstBytes = d.BurstBytes
	}
	if c.BytesPerSecond == 0 {
		c.BytesPerSecond = d.BytesPerSecond
	}
	if c.MaxPadding < 1 || c.MaxPadding > 1400 || c.BurstBytes < c.MaxPadding || c.BurstBytes > 65536 || c.BytesPerSecond < 1 || c.BytesPerSecond > 65536 {
		return errors.New("HTTP/3 Padding 参数超出范围：单包 1–1400 字节，突发预算须不小于单包上限且不超过 65536 字节，补充速率 1–65536 字节/秒")
	}
	return nil
}

func (c Config) Proto(active bool) *pb.QUICPaddingConfig {
	return &pb.QUICPaddingConfig{Enabled: active && c.Enabled, MaxPadding: int32(c.MaxPadding), BurstBytes: int32(c.BurstBytes), BytesPerSecond: int32(c.BytesPerSecond)}
}

func ForConnection(v *pb.QUICPaddingConfig) (*quic.PacketPaddingConfig, error) {
	if !v.GetEnabled() {
		return nil, nil
	}
	c := Config{Enabled: true, MaxPadding: int(v.MaxPadding), BurstBytes: int(v.BurstBytes), BytesPerSecond: int(v.BytesPerSecond)}
	if err := c.Normalize(); err != nil {
		return nil, err
	}
	return &quic.PacketPaddingConfig{MaxPadding: c.MaxPadding, BurstBytes: c.BurstBytes, BytesPerSecond: c.BytesPerSecond}, nil
}
