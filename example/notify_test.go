package example

import (
	"encoding/json"
	"github.com/imroc/req/v3"
	"github.com/waas-api/api-sdk-go/crypto"
	"testing"
	"time"
)

// send notify request as platform
// shop developer never need to care about the functions in this file

var (
	platformPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDQ3DIR9C6mMC1L
vMh4y5H33m3l/Nb0VGb2Lf5YpCV8t/zXBvZ3FTJmHaRqUJmSRcdsnLK/ZcOEyJ1/
WXeRmj+AJdL5Eeax+KcJETpjiuQU8uFi+rS0aGShUMVWE8dkZ1GRpQFFaWPyk38G
7Ixgsxi4atgBBvYn9zhQbScIH9W6pD5axCg0wfEhT8cZ6GxKEcj32Zp7OF4/QXpA
0g9S3F4YMpDnYqzV1bC0irjfcyLBENZoZ9FcxXMr4P30ERPT17jWUlWq82KOFEfB
ejpvGNWQlFiYIZKFORghN4NWF3o2lX+aE+tFJBzAReMlI5sdxuH1SEhmNkYDDnpB
+rPrrCSXAgMBAAECggEBAJg0Dyz0RFaJf0jVL0aQGzSF3JKgmcj+BPZb+CGCpWro
7ZGJmmyXft3ZtipfyDpHLZgh7UT7lOscA2J9wVvTC3mIluE5QWPqr1c1PdayrZny
kXs+9hcOiF7ibJxY15J8lH3NwEpkDhkFkalrErWZbmdePUEqYJIpX9mEYdBS2r8i
hp+et+pCrdDAjK85I0F9ipQ3bYL7TCaSEb3J0W+CVQ4h0nNiPIGXUmlh1YjCtyE0
Rbw4H6lTiOKnWdpQHSCxnZrOAKQqqNJwV2jcIt1DAXpJlKsyv+EAhgercVH1pJSf
BCsAQ7fXV8STKySshNI8LCbRM2f+RZWW/TJgByYw7VkCgYEA8L0BzvsKb2fMPeDB
3/7S7ZhgV7Y+qJHq7no+ZpH8iT5tzjNXOeG5GFCrWFYGjQEb75gAuk58pkABi/z0
N8QX168WMAIrMq2BlpO2jtp0OtZnoEspdxftS+sooFpEpXh63KRXKN5M2OAvdZ46
vBmzmv+0aS5w1dfCHkYwVrZbE0UCgYEA3hnUudgQ545qXKosHWBYNIU/Tqq/ry5i
g4WMdC2paqPndazq0mIJAkiLcmIcW9aRwkKKB16K06ydhEyToSzFcnu9yELviWHR
gnfvvmB7rilz/XA0hwTl1F5RAV5nb4NPRnq/4WvAI0T3wK5r/agKN18qz1b69mVT
QlPU0bIqyCsCgYA19CZTnS/ZiAneVGEfMp1TYrM09UNVxF5C1GLn2hAfMj6p2BfU
gSJasLm2MpGFSJpaOFbxamXFXNL77NVPKkOtsy/l0pab5QcGGFTx70Pda/ANnMrO
Ri6ItUuFpLV94GKo0Kw4HJpcgOIiGjRPs/Ls6iIk8KOZSaHX5yMuS/BdgQKBgQCf
aYztAy9G9EpVTnMxdph4wfbpgNbqZvGgkvd339pMx233YXB+Jo1uzSEBrXfLVxvx
gY7OsUYVnjzE263OrnLdtAFIvvps8f/NlEZIr7m2DNzK2IFrM9G+dx/PSrIVMPty
i+IzawJSjksBSnAKdVU33x+8CCNDPQDgh4kmJapdVwKBgAdGkISm/csRlcdpn1g/
gTVMGvOJEjant7aH5ZjbShp4pRSP7V6UmNg32mgizUeQGaHTIVikT4wLKmbNhU10
vZi26r7NWGWmnS0rMB5skHloCC9VevVPlZ3YJ8TS7/xDm/9InAHd/9cE1v/OayA0
RXz0Ph8yxJGrkdowMA8Q2yiX
-----END PRIVATE KEY-----
`

	shopPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmO0VpYTOdQKx60CLlndb
agAREt+P94KknoKfj1tZ7u5S9MPc//nQdxmT9uNyzueL9iv0B6wx7hBD3FQ+FoWk
7a4aOeWEZFxSkDQphN1v6SmWJ1PgThARBe8GQbd1/vNsTWnyrx7HHzZdZstraPj+
+JyxhOpEDWawPtERsYm/ZPScVdU7DVcS2EpX+EyeCJG/NqrVzMRFw2hAu5hTbaHn
ySUocPgTMKpkXzoQz/CxuPtdPysdmU9Jcch3Rfzcljms8w83MMU+h8884bD9sjVv
bS3ZZPkpzFbGRKjgTSs62mAkQYbIrNPs5lno0EOUNzbtwh4NPPPli3IvvXnuxt8y
8wIDAQAB
-----END PUBLIC KEY-----
`
)

var (
	riskPlatformPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDpgPMjsc5PXiLb
FaxJ8GNlAoa3fPMxTtQMU2RjBrnf3AUzoVGeQV3odxOOoJZ6GK8tNtBJtXXBN31R
vvNdIQQLQ4pwKocJhd1ZhbjyMDC29EpSMYnQ8rHFlLZdRRam5ttABctFTHsOa1sL
IMN75zCUrEYjk/qmlJI0aZGls7O1IDJSwvWeO/nPDa73UtGjqy0zToUJXfH6QmxZ
iZyzSTNyEC3z1DB+JQrkbpPybIjIUcQqjOyJTZusZ3le/Gl1fiMnlEA/SMZSveLW
funh1PZJEUvRYQ0eqCSgprE/AC1NKDuPhii0xd9K+Q2TsIldi+rrcZNfVRYvvY6y
a0p2+RgPAgMBAAECggEBAJTS1STI7L91Ni4AkEDH7/GvPIGyJ6Yjoc8BT5g17z4Y
k1Am30hITTweuN5Mx9ul4/CjYPm5qAWwAjWZyK5wno03TQLUeCC/qyalrgzeXg4d
gUkFvdro9BkEAX9My3Uw6kjR6I6QglXcYrii9zT/Ut1PN5zxce29/7lcF7JO6Jjl
ZsQ2nZuz8nqmoMyNCte5slLrzIgBawAzVCVrLd4fYsplqOZdu7zRe3sxAzrjgCdj
LvzfMMVYMnIo0NJMiosP6X9smKsf+eC4R9AatRylAa3wHakC8ugut8zYV4kNRqJA
Ue6dNl5FCR54UMdt11B/8IT9oaXgXp+eVShW6kzTsZECgYEA9S3blcERvVkgvsdL
q0cFXtuT04iAIJvDMNl616LT7rCnE6fJX/tCXY3LAmuYqVm9RTG9iNW0GCY2+4dO
7WgMVhXpTR3XfsIv0ReKJbBifTPKb12RuUCiXm3Cu08bdsSaW/HpLL30NwWZ3JQR
vgwx9gGXYg4SSXpiFkqW9IvrCPMCgYEA888tjOJXJZvbJMDT9B0Avq+ab0n9UE+p
zQrayifNFrR9AElHyH3Np0qTDg1f9WE/c1CJY3QAVPFvieWq4XyRtEOBsKjMmtOH
jqkorp+t1aWP8YQrh5/LAunScTcqmHTG3sbEaTHeE/gj4agY4zry9kr7CgKj/LJv
I5dTwwAKO3UCgYEApNnFmCZtqBOiacQUw8AIA2S+O2+/Pq2ci17fMtf/ibDrVdLu
GoQVdlPdWO5BgjSdh0XPe468/bPMKkkrL4NTMBqheEGFYGxuvDcIoxi60BYfmcuf
LKEhyz4fvdON0siURRgdwQCjkM9KSb6hQ1hty0v8nmh5sUABbZ2PbDQbvzMCgYBT
GfDKrnNJzF/bnSYhdKlGVZBsEmoXL7AOxX5hnUNYU9ivekrPWaH5PX/2MDTe7HC2
G2NY1LcwPMLp27Bs/wqiyMexsTdcJnFz/NBzBNY5lh8EESrNJXgK3Cvwjv8jy9nl
IRbdTDQH1nJUfflNqlAaBuCePtwqS596ICBavO6/6QKBgG9fDG8rM8i2iydbmOKc
DpSROfRNv3G5nGGiaxF29CtXlhQV6rqjne0UsJSZ97oJ2inF6TzwE4Q2wDDMt/ea
QFgv8Npi/saVw0/nkJNzxEW7MbQOd0ekRouWqQdfc61GvlMSyafvzJImXLltGCok
ODh1UosPXy9r80xoJ0e7fYHt
-----END PRIVATE KEY-----
`
	riskShopPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz9Wbw4JrUbMy8rO3fd9w
vkL/vZgtSIiTOOSAajFvYWjXDpcWP6wfXsCgWO6Qu543qNSzEMSM4EmnoTHTbE1y
37DtqN6ZJ+1c6H9JD/FuKSj0Wq5zaFe6jb0YdC28G9m888LpdZFKLx7+zDDusCEJ
gt0DFiTM95fFj+cM+2gJ6SPQxs2nouDzvP5co9LwQBrkdJnSFxOcetiP9o+Zx5e6
WbLiyImv6TqXOxRytxdvPEpiAqZokY8+Fiy6gsbihWVu4RGM86HXX+JsT8nVwe9U
/GP7De64n894T7mrx4eqWG8g7zIztESQidXD5xBOzoA4KxVgBubLhDy9hU3t2aCW
cQIDAQAB
-----END PUBLIC KEY-----
`
)

func Test_PlatformNotify_Deposit(t *testing.T) {
	data := map[string]interface{}{
		"address":       "TJkJ6c96DtF17J2QVk7cHWuVzas68gTWtw",
		"amount":        "10.0089",
		"chain":         "trx",
		"coin":          "trx",
		"confirm_count": 3,
		"fee":           "0",
		"from_address":  "TRWgva6duxGdcrqwUzMfyfb5H2TWWyiMc",
		"order_id":      "20220601222939629606",
		"status":        1,
		"time":          time.Now().Unix(),
		"total":         "3",
		"txid":          "13a13382dd464962f9cd9de281163ca6cd3dbc413312bfe46b2ab8786fa7b0c9",
		"type":          2,
	}
	err, sign := crypto.ApiSign(crypto.ParseObjectToClassMap(data), platformPrivateKey)
	if err != nil {
		panic(err)
	}
	params := map[string]interface{}{
		"sign": sign,
		"data": data,
	}
	params["sign"] = sign
	bs, err := json.Marshal(params)
	t.Log("request:\n", string(bs), err)

	post, err := req.R().SetBodyJsonMarshal(params).Post("http://127.0.0.1:8080/callback/deposit")
	if err != nil {
		panic(err)
	}
	var resBase struct {
		Sign   string
		Status int
		Data   json.RawMessage
	}
	err = post.UnmarshalJson(&resBase)
	t.Log("response:\n", post.String(), err)
	if resBase.Status == 200 {
		err = crypto.ApiVerifySign(crypto.ParseJsonToClassMap(string(resBase.Data)), shopPublicKey, resBase.Sign)
		if err != nil {
			panic(err)
		}
	}
}

func Test_PlatformNotify_Withdraw(t *testing.T) {
	data := map[string]interface{}{
		"address":  "TR6HJHjNUN3mvbRZ1BfjrcAfHEXDHhfvNa",
		"amount":   "0.5",
		"chain":    "trx",
		"coin":     "trx",
		"fee":      "0",
		"msg":      "提现成功",
		"status":   1,
		"time":     "1687514554",
		"total":    "0.5",
		"trade_id": "12345678",
		"txid":     "e12cf23b40fc26bff3cfcd5d44c50560bf3096cb063c2d3cc3de1adg316724a8",
		"type":     2,
	}
	err, sign := crypto.ApiSign(crypto.ParseObjectToClassMap(data), platformPrivateKey)
	if err != nil {
		panic(err)
	}
	params := map[string]interface{}{
		"sign": sign,
		"data": data,
	}
	params["sign"] = sign
	bs, err := json.Marshal(params)
	t.Log("request:\n", string(bs), err)

	post, err := req.R().SetBodyJsonMarshal(params).Post("http://127.0.0.1:8080/callback/withdraw")
	if err != nil {
		panic(err)
	}
	var resBase struct {
		Sign   string
		Status int
		Data   json.RawMessage
	}
	err = post.UnmarshalJson(&resBase)
	t.Log("response:\n", post.String(), err)
	if resBase.Status == 200 {
		err = crypto.ApiVerifySign(crypto.ParseJsonToClassMap(string(resBase.Data)), shopPublicKey, resBase.Sign)
		if err != nil {
			panic(err)
		}
	}
}

func Test_PlatformNotify_WithdrawRisk(t *testing.T) {
	data := map[string]interface{}{
		"amount":      "2.00000000",
		"coin_symbol": "usdt_trc20",
		"address":     "TLhdZuFU1fDPnzxPoXfJ6WZZMpKzY15DUi",
		"user_id":     "123",
		"order_id":    "1394934189494173697",
		"timestamp":   "1621493658",
	}
	err, sign := crypto.ApiSign(crypto.ParseObjectToClassMap(data), riskPlatformPrivateKey)
	if err != nil {
		panic(err)
	}
	params := map[string]interface{}{
		"sign": sign,
		"data": data,
	}
	params["sign"] = sign
	bs, err := json.Marshal(params)
	t.Log("request:\n", string(bs), err)

	post, err := req.R().SetBodyJsonMarshal(params).Post("http://127.0.0.1:8080/callback/withdraw/risk")
	if err != nil {
		panic(err)
	}
	var resBase struct {
		Sign   string
		Status int
		Data   json.RawMessage
	}
	err = post.UnmarshalJson(&resBase)
	t.Log("response:\n", post.String(), err)
	if resBase.Status == 200 {
		err = crypto.ApiVerifySign(crypto.ParseJsonToClassMap(string(resBase.Data)), riskShopPublicKey, resBase.Sign)
		if err != nil {
			panic(err)
		}
	}
}
