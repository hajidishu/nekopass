package control

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Store money as integer CNY cents throughout the API/database. Decimal input
// is parsed as text so a binary floating-point rounding error cannot debit money.
const maxMoneyCents int64 = 100000000000 // 1 billion CNY per wallet.

var moneyPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,9})(\.[0-9]{1,2})?$`)

func parseMoney(raw string) (int64, error) {
	if !moneyPattern.MatchString(raw) {
		return 0, errors.New("金额须为非负数，最多两位小数")
	}
	parts := strings.SplitN(raw, ".", 2)
	yuan, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, errors.New("金额超出范围")
	}
	var fraction int64
	if len(parts) == 2 {
		value := parts[1]
		if len(value) == 1 {
			value += "0"
		}
		fraction, _ = strconv.ParseInt(value, 10, 64)
	}
	cents := yuan*100 + fraction
	if cents > maxMoneyCents {
		return 0, errors.New("金额超出范围")
	}
	return cents, nil
}

func formatMoney(cents int64) string {
	if cents < 0 {
		return "-" + formatMoney(-cents)
	}
	return fmt.Sprintf("%d.%02d", cents/100, cents%100)
}

var billingMonths = map[string]int{
	"monthly": 1, "quarterly": 3, "semiannual": 6, "annual": 12,
	"biennial": 24, "triennial": 36, "onetime": 0,
}

var billingNames = map[string]string{
	"monthly": "月付", "quarterly": "季付", "semiannual": "半年付", "annual": "年付",
	"biennial": "两年付", "triennial": "三年付", "onetime": "一次性",
}

func parsePlanPrices(raw map[string]*string) (map[string]int64, error) {
	prices := make(map[string]int64)
	for cycle, value := range raw {
		if _, ok := billingMonths[cycle]; !ok {
			return nil, errors.New("不支持的付款周期")
		}
		if value == nil || *value == "" {
			continue
		}
		cents, err := parseMoney(*value)
		if err != nil {
			return nil, fmt.Errorf("%s售价：%w", billingNames[cycle], err)
		}
		prices[cycle] = cents
	}
	return prices, nil
}
