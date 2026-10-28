package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	pb "github.com/nekopass/nekopass/internal/protocol"
	"github.com/nekopass/nekopass/internal/tunnel"
	"github.com/nekopass/nekopass/internal/tunnelcrypto"
)

type TunnelRandomConfig struct {
	Cipher string `json:"cipher"`
	Key    string `json:"key"`
}

func defaultTunnelRandom() TunnelRandomConfig {
	return TunnelRandomConfig{Cipher: tunnelcrypto.ChaCha20Poly1305}
}

func (v *TunnelRandomConfig) normalize(generate bool) error {
	if v.Cipher == "" {
		v.Cipher = tunnelcrypto.ChaCha20Poly1305
	}
	if !tunnelcrypto.ValidCipher(v.Cipher) {
		return errors.New("全随机加密算法无效")
	}
	v.Key = strings.TrimSpace(v.Key)
	if v.Key == "" {
		if generate {
			var err error
			v.Key, err = tunnelcrypto.GenerateKey()
			return err
		}
		return nil
	}
	key, err := tunnelcrypto.DecodeKey(v.Key)
	if err != nil {
		return errors.New("加密密钥须为 Base64 编码的 32 字节密钥；留空自动生成")
	}
	v.Key = base64.RawURLEncoding.EncodeToString(key)
	return nil
}

func prepareNodeRandom(ctx context.Context, tx pgx.Tx, id int64, input *NodeInput) error {
	cfg := defaultTunnelRandom()
	if input.Random != nil {
		cfg = *input.Random
	} else {
		var data []byte
		if err := tx.QueryRow(ctx, "SELECT random_config FROM nodes WHERE id=$1", id).Scan(&data); err != nil {
			return err
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return err
		}
	}
	if err := cfg.normalize(tunnel.Random(input.TunnelProtocol) || input.Random != nil); err != nil {
		return err
	}
	input.Random = &cfg
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "UPDATE nodes SET random_config=$2 WHERE id=$1", id, data)
	return err
}

func appendRandomControl(ctx context.Context, tx pgx.Tx, nodeID int64, out *pb.ControlMessage) error {
	cache := map[int64]*pb.RandomConfig{}
	load := func(id int64) (*pb.RandomConfig, error) {
		if cfg, ok := cache[id]; ok {
			return cfg, nil
		}
		var data []byte
		if err := tx.QueryRow(ctx, "SELECT random_config FROM nodes WHERE id=$1", id).Scan(&data); err != nil {
			return nil, err
		}
		cfg := defaultTunnelRandom()
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, err
		}
		if err := cfg.normalize(false); err != nil {
			return nil, err
		}
		if cfg.Key == "" {
			return nil, errors.New("random encryption key not configured")
		}
		p := &pb.RandomConfig{Cipher: cfg.Cipher, Key: cfg.Key}
		cache[id] = p
		return p, nil
	}
	var err error
	if tunnel.Random(out.Node.TunnelProtocol) {
		if out.Node.Random, err = load(nodeID); err != nil {
			return err
		}
	}
	for _, rule := range out.Rules {
		if rule.EgressNodeId != 0 && tunnel.Random(rule.TunnelProtocol) {
			if rule.Random, err = load(rule.EgressNodeId); err != nil {
				return err
			}
		}
	}
	return nil
}
