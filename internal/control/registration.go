package control

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nekopass/nekopass/internal/registration"
	"golang.org/x/crypto/bcrypt"
)

func formatID(id int64) string { return strconv.FormatInt(id, 10) }

func (s *Server) registrationConfig(w http.ResponseWriter, r *http.Request) {
	v, err := s.readSettings(r.Context())
	if err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"enabled": v.RegistrationEnabled, "captcha_mode": v.CaptchaMode, "email_verification": v.RegistrationEmailVerification, "force_invite": v.ForceInvite && v.ReferralEnabled, "terms_url": v.TermsURL, "privacy_url": v.PrivacyURL})
}

func (s *Server) registrationSettings(w http.ResponseWriter, r *http.Request) (SystemSettings, bool) {
	v, err := s.readSettings(r.Context())
	if err != nil {
		s.dbError(w, err)
		return v, false
	}
	if !v.RegistrationEnabled {
		fail(w, 403, "此站点未开放注册")
		return v, false
	}
	return v, true
}

func (s *Server) captcha(w http.ResponseWriter, r *http.Request) {
	v, ok := s.registrationSettings(w, r)
	if !ok {
		return
	}
	s.issueCaptcha(w, r, v, "registration", 0)
}

func (s *Server) sendRegistrationCode(w http.ResponseWriter, r *http.Request) {
	v, ok := s.registrationSettings(w, r)
	if !ok {
		return
	}
	if !v.RegistrationEmailVerification {
		fail(w, 403, "本站已关闭注册邮件验证")
		return
	}
	var in struct {
		Email     string `json:"email"`
		CaptchaID string `json:"captcha_id"`
		Captcha   string `json:"captcha"`
		Invite    string `json:"invite_code"`
	}
	if !decode(w, r, &in) {
		return
	}
	email, err := registration.Email(in.Email)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if !s.allowLogin("mail-ip:"+s.clientIP(r), time.Now(), 3) || !s.allowLogin("mail-all", time.Now(), 20) {
		fail(w, 429, "发送请求过于频繁")
		return
	}
	if len(in.Invite) > 128 {
		fail(w, 400, "邀请码过长")
		return
	}
	if v.ForceInvite && v.ReferralEnabled {
		var valid bool
		if err = s.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM users WHERE invite_code=$1 AND enabled)", strings.TrimSpace(in.Invite)).Scan(&valid); err != nil {
			s.dbError(w, err)
			return
		}
		if !valid {
			fail(w, 400, "本站仅允许邀请注册，请填写有效邀请码")
			return
		}
	}
	select {
	case s.mailWorkers <- struct{}{}:
		defer func() { <-s.mailWorkers }()
	default:
		fail(w, 429, "邮件发送繁忙，请稍后重试")
		return
	}
	if err = v.SMTP.Validate(true); err != nil {
		fail(w, 503, "邮件服务未配置，请联系管理员")
		return
	}
	if !s.verifyCaptcha(w, r, v, "registration", 0, in.CaptchaID, in.Captcha) {
		return
	}
	token := Secret()
	code, err := registration.Digits(6)
	if err != nil {
		fail(w, 503, "验证码暂不可用")
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		s.dbError(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	// Serialize sends for one mailbox; a 60-second limit survives restarts.
	if _, err = tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock(hashtextextended($1,734295))", email); err != nil {
		s.dbError(w, err)
		return
	}
	var recent bool
	if err = tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM registration_codes WHERE email=$1 AND created_at>now()-interval '60 seconds')", email).Scan(&recent); err != nil {
		s.dbError(w, err)
		return
	}
	if recent {
		fail(w, 429, "请等待 60 秒后再发送")
		return
	}
	_, _ = tx.Exec(r.Context(), "DELETE FROM registration_codes WHERE expires_at<now()")
	if _, err = tx.Exec(r.Context(), "DELETE FROM registration_codes WHERE email=$1", email); err != nil {
		s.dbError(w, err)
		return
	}
	if _, err = tx.Exec(r.Context(), "INSERT INTO registration_codes(id,email,code_hash,expires_at) VALUES($1,$2,$3,now()+interval '10 minutes')", Hash(token), email, Hash(token+code)); err != nil {
		s.dbError(w, err)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		s.dbError(w, err)
		return
	}
	if err = s.sendMail(r.Context(), v.SMTP, email, code, v.SiteName); err != nil {
		fail(w, 503, "邮件发送失败，请检查邮箱地址或联系管理员")
		return
	}
	if _, err = s.Pool.Exec(r.Context(), "UPDATE registration_codes SET sent=true WHERE id=$1", Hash(token)); err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"verification_id": token, "retry_after": 60})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	v, ok := s.registrationSettings(w, r)
	if !ok {
		return
	}
	var in struct {
		Email     string `json:"email"`
		Password  string `json:"password"`
		Confirm   string `json:"confirm_password"`
		ID        string `json:"verification_id"`
		Code      string `json:"email_code"`
		Invite    string `json:"invite_code"`
		CaptchaID string `json:"captcha_id"`
		Captcha   string `json:"captcha"`
	}
	if !decode(w, r, &in) {
		return
	}
	email, err := registration.Email(in.Email)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if in.Password != in.Confirm || len(in.Password) < 12 || len(in.Password) > 72 {
		fail(w, 400, "密码须为 12–72 字节且两次输入相同")
		return
	}
	if (v.RegistrationEmailVerification && (!hashOK(in.ID) || len(in.Code) != 6)) || len(in.Invite) > 128 {
		fail(w, 400, "邮箱验证码或邀请码格式无效")
		return
	}
	if !s.allowLogin("register:"+s.clientIP(r), time.Now(), 5) {
		fail(w, 429, "注册请求过于频繁")
		return
	}
	emailVerified := false
	if v.RegistrationEmailVerification {
		// Commit failed attempts before password work. A correct code remains
		// consumed atomically with account creation, preventing concurrent reuse.
		var hash string
		err = s.Pool.QueryRow(r.Context(), "UPDATE registration_codes SET attempts=attempts+1 WHERE id=$1 AND email=$2 AND sent AND expires_at>now() AND attempts<5 RETURNING code_hash", Hash(in.ID), email).Scan(&hash)
		if err != nil || subtle.ConstantTimeCompare([]byte(hash), []byte(Hash(in.ID+in.Code))) != 1 {
			fail(w, 400, "邮箱验证码错误、已过期或尝试次数过多")
			return
		}
		emailVerified = true
	} else if !s.verifyCaptcha(w, r, v, "registration", 0, in.CaptchaID, in.Captcha) {
		return
	}
	select {
	case s.loginWorkers <- struct{}{}:
		defer func() { <-s.loginWorkers }()
	default:
		fail(w, 429, "注册请求繁忙，请稍后重试")
		return
	}
	password, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		fail(w, 400, "密码无效")
		return
	}
	tx, err := s.ruleTx(r.Context())
	if err != nil {
		s.dbError(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	settings, err := readSystemSettings(r.Context(), tx)
	if err != nil {
		s.dbError(w, err)
		return
	}
	if !settings.RegistrationEnabled {
		fail(w, 403, "此站点未开放注册")
		return
	}
	if settings.RegistrationEmailVerification != v.RegistrationEmailVerification || (!settings.RegistrationEmailVerification && settings.CaptchaMode != v.CaptchaMode) {
		fail(w, 409, "注册验证设置已变更，请刷新后重试")
		return
	}

	if _, err = tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock(hashtextextended($1,734296))", email); err != nil {
		s.dbError(w, err)
		return
	}
	var exists bool
	if err = tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM users WHERE lower(username)=$1)", email).Scan(&exists); err != nil {
		s.dbError(w, err)
		return
	}
	if exists {
		fail(w, 409, "此邮箱已注册")
		return
	}
	if emailVerified {
		var consumed string
		err = tx.QueryRow(r.Context(), "DELETE FROM registration_codes WHERE id=$1 AND email=$2 AND code_hash=$3 AND sent AND expires_at>now() RETURNING id", Hash(in.ID), email, Hash(in.ID+in.Code)).Scan(&consumed)
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, 400, "邮箱验证码已失效")
			return
		}
		if err != nil {
			s.dbError(w, err)
			return
		}
	}
	var inviter *int64
	if strings.TrimSpace(in.Invite) != "" {
		var id int64
		err = tx.QueryRow(r.Context(), "SELECT id FROM users WHERE invite_code=$1 AND enabled", strings.TrimSpace(in.Invite)).Scan(&id)
		if err == nil {
			inviter = &id
		} else if !errors.Is(err, pgx.ErrNoRows) {
			s.dbError(w, err)
			return
		}
	}
	if settings.ForceInvite && settings.ReferralEnabled && inviter == nil {
		fail(w, 400, "本站仅允许邀请注册，请填写有效邀请码")
		return
	}
	var uid int64
	if err = tx.QueryRow(r.Context(), "INSERT INTO users(username,password_hash,email_verified_at,invite_code,inviter_id) VALUES($1,$2,CASE WHEN $5::boolean THEN now() ELSE NULL END,$3,$4) RETURNING id", email, string(password), Secret()[:16], inviter, emailVerified).Scan(&uid); err != nil {
		s.dbError(w, err)
		return
	}

	if err = tx.Commit(r.Context()); err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": uid, "username": email})
}
