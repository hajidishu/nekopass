package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type User struct {
	ID       int64  `json:"id"`
	IsBot    bool   `json:"is_bot"`
	Username string `json:"username"`
}
type Chat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}
type Message struct {
	ID            int64           `json:"message_id"`
	Date          int64           `json:"date"`
	From          *User           `json:"from"`
	Chat          Chat            `json:"chat"`
	Text          string          `json:"text"`
	SenderChat    *Chat           `json:"sender_chat"`
	ForwardOrigin json.RawMessage `json:"forward_origin"`
}
type Callback struct {
	ID              string   `json:"id"`
	From            User     `json:"from"`
	Message         *Message `json:"message"`
	InlineMessageID string   `json:"inline_message_id"`
	Data            string   `json:"data"`
}
type Update struct {
	ID       int64     `json:"update_id"`
	Message  *Message  `json:"message"`
	Callback *Callback `json:"callback_query"`
}
type Button struct {
	Text string `json:"text"`
	Data string `json:"callback_data,omitempty"`
	URL  string `json:"url,omitempty"`
}
type Keyboard struct {
	Rows [][]Button `json:"inline_keyboard"`
}
type API interface {
	Me(context.Context) (User, error)
	Prepare(context.Context) error
	Updates(context.Context, int64) ([]Update, error)
	Send(context.Context, int64, string, *Keyboard) error
	Edit(context.Context, int64, int64, string, *Keyboard) error
	Answer(context.Context, string, string) error
}
type APIError struct {
	Code       int
	RetryAfter int
}

var errLargeResponse = errors.New("Telegram 响应超出大小限制")

func (e *APIError) Error() string { return fmt.Sprintf("Telegram 返回错误（%d）", e.Code) }

type Client struct {
	token, baseURL string
	http           *http.Client
}

func NewClient(token string) API {
	return &Client{token: token, baseURL: "https://api.telegram.org", http: &http.Client{Timeout: 40 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *Client) call(ctx context.Context, method string, body any, out any) error {
	if method != "getUpdates" {
		short, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		ctx = short
	}
	data, err := json.Marshal(body)
	if err != nil {
		return errors.New("Telegram 请求内容无效")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/bot"+c.token+"/"+method, bytes.NewReader(data))
	if err != nil {
		return errors.New("Telegram 请求无法创建")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	// net/http errors contain the request URL, including the credential. Never return them.
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("无法连接 Telegram")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if len(raw) > 2<<20 {
		return errLargeResponse
	}
	if err != nil {
		return errors.New("Telegram 响应无法读取")
	}
	var envelope struct {
		OK         bool            `json:"ok"`
		Result     json.RawMessage `json:"result"`
		Code       int             `json:"error_code"`
		Parameters struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return errors.New("Telegram 响应格式无效")
	}
	if resp.StatusCode != 200 || !envelope.OK {
		code := envelope.Code
		if code == 0 {
			code = resp.StatusCode
		}
		return &APIError{Code: code, RetryAfter: envelope.Parameters.RetryAfter}
	}
	if out != nil && json.Unmarshal(envelope.Result, out) != nil {
		return errors.New("Telegram 返回内容无效")
	}
	return nil
}
func (c *Client) Me(ctx context.Context) (User, error) {
	var u User
	err := c.call(ctx, "getMe", struct{}{}, &u)
	return u, err
}
func (c *Client) Prepare(ctx context.Context) error {
	return c.call(ctx, "deleteWebhook", map[string]bool{"drop_pending_updates": false}, nil)
}
func (c *Client) Updates(ctx context.Context, offset int64) ([]Update, error) {
	var v []Update
	err := c.call(ctx, "getUpdates", map[string]any{"offset": offset, "limit": 100, "timeout": 25, "allowed_updates": []string{"message", "callback_query"}}, &v)
	if errors.Is(err, errLargeResponse) {
		err = c.call(ctx, "getUpdates", map[string]any{"offset": offset, "limit": 1, "timeout": 25, "allowed_updates": []string{"message", "callback_query"}}, &v)
	}
	return v, err
}
func messageBody(chat int64, text string, keyboard *Keyboard) map[string]any {
	v := map[string]any{"chat_id": chat, "text": text, "parse_mode": "HTML", "protect_content": true, "link_preview_options": map[string]bool{"is_disabled": true}}
	if keyboard != nil {
		v["reply_markup"] = keyboard
	}
	return v
}
func (c *Client) Send(ctx context.Context, chat int64, text string, k *Keyboard) error {
	return c.call(ctx, "sendMessage", messageBody(chat, text, k), nil)
}
func (c *Client) Edit(ctx context.Context, chat, message int64, text string, k *Keyboard) error {
	v := messageBody(chat, text, k)
	delete(v, "protect_content")
	v["message_id"] = message
	return c.call(ctx, "editMessageText", v, nil)
}
func (c *Client) Answer(ctx context.Context, id, text string) error {
	return c.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": id, "text": text, "show_alert": text != ""}, nil)
}
