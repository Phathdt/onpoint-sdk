package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
)

func HmacSHA256(payload string, appSecret string) string {
	secret := []byte(appSecret)
	bb := []byte(payload)
	hash := hmac.New(sha256.New, secret)
	hash.Write(bb)

	sum := hash.Sum(nil)
	return strings.ToUpper(hex.EncodeToString(sum))
}

func Sign(data url.Values, appSecret string) string {
	var keys []string
	for key := range data {
		keys = append(keys, key)
	}

	sort.StringSlice(keys).Sort()

	payload := ""
	for _, key := range keys {
		if data.Get(key) != "" {
			payload = payload + key + data.Get(key)
		}
	}

	return HmacSHA256(payload, appSecret)
}
