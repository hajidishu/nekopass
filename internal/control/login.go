package control

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nekopass/nekopass/internal/store"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

var errLoginChanged = errors.New("login credentials changed during authentication")

// Unknown/disabled accounts still perform password work. This is a random,
// unusable comparison hash, never an account or a default login credential.
var dummyLoginHash = func() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte(Secret()), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return hash
}()

const maxLoginBuckets = 8192

// Keyed fixed slots bound storage without refusing every new source at capacity.
// IP and account limits occupy separate halves. Collisions share a limit, so
// rotating names cannot evict or reset the limiter for an existing account.
func (s *Server) loginSlot(key string) string {
	group := "account:"
	if strings.HasPrefix(key, "ip:") {
		group = "ip:"
	}
	mac := hmac.New(sha256.New, s.loginBucketKey[:])
	mac.Write([]byte(key))
	slot := binary.BigEndian.Uint16(mac.Sum(nil)[:2]) % (maxLoginBuckets / 2)
	return group + strconv.Itoa(int(slot))
}

func (s *Server) allowLogin(key string, now time.Time, burst int) bool {
	key = s.loginSlot(key)
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	if now.Sub(s.loginPruned) >= time.Minute {
		for key, bucket := range s.loginBuckets {
			if now.Sub(bucket.seen) > 10*time.Minute {
				delete(s.loginBuckets, key)
			}
		}
		s.loginPruned = now
	}
	bucket := s.loginBuckets[key]
	if bucket == nil {
		bucket = &loginBucket{limiter: rate.NewLimiter(rate.Every(12*time.Second), burst)}
		s.loginBuckets[key] = bucket
	}
	bucket.seen = now
	return bucket.limiter.AllowN(now, 1)
}

func (s *Server) createLoginSession(ctx context.Context, user store.User, token string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var id int64
	// Password reset/disable takes the same user row FOR UPDATE. Holding this
	// share lock until session insertion commits makes both orderings safe:
	// a reset first rejects old credentials; a reset later deletes the new session.
	err = tx.QueryRow(ctx, "SELECT id FROM users WHERE id=$1 AND enabled AND password_hash=$2 FOR SHARE", user.ID, user.PasswordHash).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return errLoginChanged
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO sessions(token_hash,user_id,expires_at,cookie_renewed_at) VALUES($1,$2,NULL,now())", Hash(token), id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
