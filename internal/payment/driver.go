// Package payment contains gateway contracts and a registry. Payment methods
// are administrator-owned configurations, not gateway implementations.
package payment

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
)

type Config map[string]string
type Field struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder"`
	Secret      bool   `json:"secret"`
	Required    bool   `json:"required"`
}
type Definition struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Fields []Field `json:"fields"`
}
type Order struct{ Number, Amount, Currency, Name, NotifyURL, ReturnURL string }
type Checkout struct {
	URL string `json:"url"`
}
type Callback struct {
	Query  url.Values
	Body   []byte
	Header http.Header
	Method string
}
type Receipt struct{ OrderNumber, TradeNumber, Amount, Currency string }
type Response struct {
	Status            int
	ContentType, Body string
}

type Driver interface {
	Definition() Definition
	Validate(Config) error
	AccountScope(Config) string
	Create(context.Context, Config, Order) (Checkout, error)
	Reference(Callback) (string, error)
	Verify(Config, Callback) (Receipt, error)
	Acknowledge(bool) Response
}

type Registry struct{ drivers map[string]Driver }

func NewRegistry(drivers ...Driver) *Registry {
	r := &Registry{drivers: map[string]Driver{}}
	for _, driver := range drivers {
		id := driver.Definition().ID
		if id == "" || r.drivers[id] != nil {
			panic("duplicate or empty payment driver")
		}
		r.drivers[id] = driver
	}
	return r
}
func (r *Registry) Driver(id string) (Driver, error) {
	d := r.drivers[id]
	if d == nil {
		return nil, errors.New("不支持的支付接口")
	}
	return d, nil
}
func (r *Registry) Definitions() []Definition {
	result := []Definition{}
	for _, d := range r.drivers {
		result = append(result, d.Definition())
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
