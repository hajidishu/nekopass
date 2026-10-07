package registration

import (
	"bytes"
	"crypto/rand"
	"image"
	"image/color"
	"image/png"
	"math/big"
)

func Digits(n int) (string, error) {
	value := make([]byte, n)
	for i := range value {
		d, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		value[i] = '0' + byte(d.Int64())
	}
	return string(value), nil
}

var digits = [10][7]string{
	{"01110", "10001", "10011", "10101", "11001", "10001", "01110"},
	{"00100", "01100", "00100", "00100", "00100", "00100", "01110"},
	{"01110", "10001", "00001", "00010", "00100", "01000", "11111"},
	{"11110", "00001", "00001", "01110", "00001", "00001", "11110"},
	{"00010", "00110", "01010", "10010", "11111", "00010", "00010"},
	{"11111", "10000", "10000", "11110", "00001", "00001", "11110"},
	{"01110", "10000", "10000", "11110", "10001", "10001", "01110"},
	{"11111", "00001", "00010", "00100", "01000", "01000", "01000"},
	{"01110", "10001", "10001", "01110", "10001", "10001", "01110"},
	{"01110", "10001", "10001", "01111", "00001", "00001", "01110"},
}

func Image(code string) ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, 160, 50))
	noise := make([]byte, 512)
	if _, err := rand.Read(noise); err != nil {
		return nil, err
	}
	for y := 0; y < 50; y++ {
		for x := 0; x < 160; x++ {
			img.Set(x, y, color.RGBA{230, 239, 250, 255})
		}
	}
	for i, c := range code {
		pattern := digits[c-'0']
		offset := int(noise[i] % 8)
		for y, row := range pattern {
			for x, pixel := range row {
				if pixel == '1' {
					for a := 0; a < 3; a++ {
						for b := 0; b < 3; b++ {
							img.Set(8+i*24+x*3+a+(y-3)/3, 8+offset+y*3+b, color.RGBA{25, 50, 100, 255})
						}
					}
				}
			}
		}
	}
	for i := 0; i+1 < len(noise); i += 2 {
		img.Set(int(noise[i])%160, int(noise[i+1])%50, color.RGBA{100, 140, 190, 255})
	}
	var out bytes.Buffer
	err := png.Encode(&out, img)
	return out.Bytes(), err
}
