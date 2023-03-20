package signature

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/tidwall/gjson"
	"sort"
)

// ApiSign generate data sign
//
//	@param data api param data
//	@param priKey rsa private key
//	@return error
//	@return string
func ApiSign(data map[string]string, priKey string) (error, string) {
	hashed := genSignString(data)
	// rsa
	block, _ := pem.Decode([]byte(priKey))
	if block == nil {
		return errors.New("private key error"), ""
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err, ""
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey.(*rsa.PrivateKey), crypto.MD5, hashed)
	if err != nil {
		return err, ""
	}
	ciphertext := base64.StdEncoding.EncodeToString(signature)

	return nil, ciphertext
}

// ApiVerifySign verify sign
//
//	@param data api response data
//	@param pubKey public key
//	@param signStr sign string
//	@return error
func ApiVerifySign(data map[string]string, pubKey string, signStr string) error {
	hashed := genSignString(data)
	block, _ := pem.Decode([]byte(pubKey))
	if block == nil {
		return errors.New("public key error")
	}
	// 解析公钥
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	pub := pubInterface.(*rsa.PublicKey)

	decodeString, err := base64.StdEncoding.DecodeString(signStr)
	if err != nil {
		return err
	}
	err = rsa.VerifyPKCS1v15(pub, crypto.MD5, hashed, decodeString)
	if err != nil {
		return err
	}

	return nil
}

// join params as string
func genSignString(data map[string]string) []byte {
	delete(data, "sign")
	var keys []string
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var signStr string
	for _, k := range keys {
		if signStr != "" {
			signStr = signStr + "&" + k + "=" + data[k]
		} else {
			signStr = k + "=" + data[k]
		}
	}

	fmt.Println("joined string: ", signStr)

	hashMd5 := md5.Sum([]byte(signStr))
	hashed := hashMd5[:]

	return hashed
}

// ParseJsonToClassMap convert json string to map[string]string
func ParseJsonToClassMap(jsonStr string) (m map[string]string) {
	m = make(map[string]string)
	result := gjson.Parse(jsonStr)
	result.ForEach(func(key, value gjson.Result) bool {
		if value.Type == gjson.JSON && gjson.Valid(value.String()) {
			m[key.String()] = jsonToString(value.String())
		} else {
			m[key.String()] = value.String()
		}
		return true
	})
	return
}

func jsonToString(jsonStr string) string {
	str := ""
	r := gjson.Parse(jsonStr)
	r.ForEach(func(key, value gjson.Result) bool {
		if value.Type == gjson.JSON && gjson.Valid(value.String()) {
			str += jsonToString(value.String())
		} else {
			str += value.String()
		}
		return true
	})
	return str
}
