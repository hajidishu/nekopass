package control

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/nekopass/nekopass/internal/registration"
)

func (s *Server) issueCaptcha(w http.ResponseWriter, r *http.Request, settings SystemSettings, purpose string, userID int64) {
	if settings.CaptchaMode != "image" {
		writeJSON(w, 200, map[string]string{"mode": "off"})
		return
	}
	if !s.allowLogin("captcha:"+s.clientIP(r), time.Now(), 10) {
		fail(w, 429, "验证码请求过于频繁")
		return
	}
	code, err := registration.Digits(6)
	if err != nil {
		fail(w, 503, "验证码暂不可用")
		return
	}
	png, err := registration.Image(code)
	if err != nil {
		fail(w, 503, "验证码暂不可用")
		return
	}
	id := Secret()
	if _, err = s.Pool.Exec(r.Context(), "INSERT INTO registration_captchas(id,answer_hash,remote_key,expires_at,purpose,user_id) VALUES($1,$2,$3,now()+interval '5 minutes',$4,NULLIF($5,0))", Hash(id), Hash(id+code), Hash(s.clientIP(r)), purpose, userID); err != nil {
		s.dbError(w, err)
		return
	}
	_, _ = s.Pool.Exec(r.Context(), "DELETE FROM registration_captchas WHERE expires_at<now()")
	writeJSON(w, 200, map[string]string{"id": id, "image": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)})
}

func (s *Server) verifyCaptcha(w http.ResponseWriter, r *http.Request, settings SystemSettings, purpose string, userID int64, id, answer string) bool {
	if settings.CaptchaMode == "off" {
		return true
	}
	if settings.CaptchaMode != "image" {
		fail(w, 503, "人机验证暂不可用")
		return false
	}
	var hash string
	err := s.Pool.QueryRow(r.Context(), "DELETE FROM registration_captchas WHERE id=$1 AND remote_key=$2 AND purpose=$3 AND COALESCE(user_id,0)=$4 AND expires_at>now() RETURNING answer_hash", Hash(id), Hash(s.clientIP(r)), purpose, userID).Scan(&hash)
	if err != nil || !hashOK(id) || len(answer) != 6 || subtle.ConstantTimeCompare([]byte(hash), []byte(Hash(id+answer))) != 1 {
		fail(w, 400, "图形验证码错误或已过期，请刷新")
		return false
	}
	return true
}
