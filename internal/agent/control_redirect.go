package agent

import (
	"encoding/json"
	"errors"

	bolt "go.etcd.io/bbolt"
)

type controlRedirect struct{ endpoint string }

func (e *controlRedirect) Error() string { return "control endpoint changed" }

func (e *Engine) redirectedControlEndpoint(origin string) (string, error) {
	var saved struct{ Origin, Endpoint string }
	err := e.state.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket([]byte("meta")).Get([]byte("control-endpoint"))
		if len(data) == 0 {
			return nil
		}
		return json.Unmarshal(data, &saved)
	})
	if err != nil {
		return "", err
	}
	if saved.Origin != origin || saved.Endpoint == "" {
		return origin, nil
	}
	if _, _, err := controlEndpoint(saved.Endpoint); err != nil {
		return "", errors.New("invalid stored control endpoint")
	}
	return saved.Endpoint, nil
}

func (e *Engine) saveControlEndpoint(origin, endpoint string) error {
	if _, _, err := controlEndpoint(endpoint); err != nil {
		return err
	}
	data, err := json.Marshal(struct{ Origin, Endpoint string }{origin, endpoint})
	if err != nil {
		return err
	}
	return e.state.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("meta")).Put([]byte("control-endpoint"), data) })
}
