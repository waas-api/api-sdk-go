package callback_server

import (
	"encoding/json"
	"github.com/imroc/req/v3"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net/http"
	"os"
	"testing"
	"waas/signature"
)

var (
	testServerConf ServerConfig
)

func init() {
	bs, err := os.ReadFile("../config_example.yaml")
	if err != nil {
		panic(err)
	}
	var it struct {
		CallbackServerConfig ServerConfig `json:"callback_server_config" yaml:"callback_server_config"`
	}
	err = yaml.Unmarshal(bs, &it)
	if err != nil {
		panic(err)
	}
	testServerConf = it.CallbackServerConfig
}

// shop callback server example handler
func Test_CallbackServer(t *testing.T) {

	http.HandleFunc("/callback/deposit", func(w http.ResponseWriter, r *http.Request) {

		// this block can be in web server middleware or your custom controller
		{
			bs, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(400)
				w.Write([]byte(err.Error()))
				return
			}
			t.Log("Request Body:", string(bs))

			// check request sign
			if err := signature.CallbackServerVerifyRequestSign(bs, testServerConf.PlatformPublicKey); err != nil {
				w.WriteHeader(500)
				w.Write([]byte(err.Error()))
				return
			}
		}

		// your business code
		resStruct := struct {
			Status int         `json:"status"`
			Data   interface{} `json:"data"`
			Sign   string      `json:"sign"`
		}{
			Status: 200,
			Data: map[string]interface{}{
				"success_data": "success",
			},
		}

		// this block can be in web server middleware or your custom controller
		{
			resBytes, err := json.Marshal(resStruct)
			if err != nil {
				w.WriteHeader(500)
				w.Write([]byte(err.Error()))
				return
			}
			// generate sign for response
			signedRes, err := signature.CallbackServerGenResponseSign(resBytes, testServerConf.PrivateKey)
			if err != nil {
				w.WriteHeader(500)
				w.Write([]byte(err.Error()))
				return
			}
			resBytes = signedRes.([]byte)
			t.Log("Response Body:", string(resBytes))
			w.WriteHeader(200)
			w.Write(resBytes)
		}
	})

	log.Println("Starting server at port 8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

// another shop callback server implementation, handle sign in your custom controller.
func Test_CallbackServer2(t *testing.T) {

	http.HandleFunc("/callback/deposit", func(w http.ResponseWriter, r *http.Request) {

		reqStruct := struct {
			Data interface{} `json:"data"`
			Sign string      `json:"sign"`
		}{}
		resStruct := struct {
			Status int         `json:"status"`
			Data   interface{} `json:"data"`
			Sign   string      `json:"sign"`
		}{}

		// bind request body, implement detail depends on your server framework.
		{
			bs, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(400)
				w.Write([]byte(err.Error()))
				return
			}
			t.Log("Request Body:", string(bs))
			json.Unmarshal(bs, &reqStruct)
		}

		{
			// check request sign
			if err := signature.CallbackServerVerifyRequestSign(reqStruct, testServerConf.PlatformPublicKey); err != nil {
				w.WriteHeader(500)
				w.Write([]byte(err.Error()))
				return
			}

			// your business code
			resStruct.Status = 200
			resStruct.Data = map[string]interface{}{
				"success_data": "success",
			}

			// generate sign for response
			if sign, err := signature.CallbackServerGenResponseSignOnly(resStruct.Data, testServerConf.PrivateKey); err != nil {
				w.WriteHeader(500)
				w.Write([]byte(err.Error()))
				return
			} else {
				resStruct.Sign = sign
			}
		}

		// write response body, implement detail depends on your server framework.
		{
			resBytes, _ := json.Marshal(resStruct)
			t.Log("Response Body:", string(resBytes))
			w.WriteHeader(200)
			w.Write(resBytes)
		}
	})

	log.Println("Starting server at port 8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

var (
	platformPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0bEb9/KyK2rZK
PgTkSVfD9dLVpCQBOWfmgIdJKaLS+KbH4htijm3x7GSseBlkDOt681udO3lyDVve
u/bYo9KBKlMOLyXfMDw4Os1u17zt3b/zVHfc8hY6Qlf0qUFn6/uw5c6zG7RD7jqW
mkz8c7hk7610tFu/2DXZl5Bb+WEVxkv6+ifVM/LVqSULGqdmpbS8ldWcMwMmYaDm
5Y9JkJnraFdidW/5YzjyqBiWLj57eZo8/KHlVuDWtJO4+deCe2vN1cs4w6/yO4VA
DF+QgsfYb1gm7C9RMPiUBPcWz2gl+5TkDvWPCMFqvVKAhDmWesNUUayc5YFQikqh
U6qt+sz9AgMBAAECggEAQZADMDKMZJzblxj4YBiCyxPePII8DzHUHr/f6Wc24uE2
gfYZK3REYaAcaUvvNhs3yuL6DKXbGOXf142IQustCIDf04ywf20gxPIhSsEcx3dI
VF0CfYh/KUaIfcCvotrvCDZKKW3M0M6V/boudaJ7hDpQVtNfb9RapSpda/6wF9/t
30cTlPTmDd8mv2IzzGMCHE+I/z9IQjNOZiYqVYEghO+YhQJm7QUeLX6AnYCJxjzc
OV/2egfNjmcwJSUfSNeJKxUouN40oJ10ZbFvTg14st0K/d653fZdjyDHhRoP7aGi
08Q4RH9dCy5KIvn6gUhgaH+F+Shrbqyyp7UO74GJBQKBgQDeBkckhmgZmrlh5pIs
S57n8h1WTLEysgJrn59ybdkSkAeS/0w6qZa596xSroR6UJpvxy3N5CRR0PPU8rtp
1cl5Wcioj82n4M0QRGwK1MqUPAY2pgFo0JUDBoKhkE4U4D0pR+AE0qXrGahNHM9M
+CiFi6fatt/VjTWwZ0H/ZMB21wKBgQDQCEZTcfasr8gfQqoivPWjbFzFXhoY7vbV
oo2EQvNOfcO2LkNtUq3hFbMSpVC/GJn6GHT+9bmIwNcm7wkS6q3GsjOZa6WDIW/H
biHPH0X4E5UsWc122gr0BWJbp2c5oJqAUfJVjEkxmIqYkbPl3WwY50+dlYED83yp
kqMwdLRkSwKBgQDFQaqfZtLCPNcLhgDEXgM2a8No0wZz1feUiuLslW/QsCoqjau6
SsXhP4zYgLiuu0IaoUmurU0fa5fW0Dl2FDzGFeDS8cBzsKRAGaosDVZWUOXsU5zY
9MgPQg95X24f2gI81ODRKB3FPKxspnX/GlNWIvfkt6kyYB0dNwBJ2cetTQKBgQCw
fISlIEbkY9CEbLsH84T1GuZtbpL3WivAPEKQ1XeyvFFACmmboovvK8ia5fLl3Aot
OXhwIKlBUlB1ME9jZAL/UYki/EcTQ1egOlembuKePobMdHcyAHNQaAz0ssWJBy5r
9JmBaB1kXQQfwWR8e2fMjNhnWUF1x6iX99ZIMoojlwKBgGcz4505U4NBBKS1+eEr
kKTmJ0GKbIbPLTYO2Y2JsjgS0cHAd25u4LIz8kJrFLZ5EisPXjVSmtpmCYEH0HQs
/ekkHrLoQSXluCSAFqxQyWupHD/33RCMr35aB2O6VclK6H/SD35EERfGT4F+gTw+
bIcFnwrx3Co+oQS0ImoKzpwR
-----END PRIVATE KEY-----
`
	shopPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXtvC2pJrS0yBpOXp1kT
MXhENEPm3diOoTbj+SWD0KwEuebax9d0x7blEMi75Y64gZ58K5wNtVVKFGpt+lCp
DNp8Kbx2pOhZxbikwRkTU5Ef9+eu1MDbvUTx93tVYViih1jNOfhpRudIduh6YA9U
FPl8GfurisMDQH7059PqN9BKNNNG4RJeBKKLHjgdMti9z42qQdMUUFvKP4/JU9JN
FB3cewvar6n0UQBA9ifsPEEIMoVZBzrRi1fH9P1hoCrFDZMWrRmw/8rTL1+a9Qs9
HpS8jmm3Gtfp3fZZHNSXpLRmORFEXrrWap1os8RTRGyFW75+4e6VXvILXNOtLqZj
rwIDAQAB
-----END PUBLIC KEY-----
`
)

// send notify request as platform, shop developer no need to care about this function.
func Test_PlatformNotify(t *testing.T) {
	data := map[string]string{
		"order_id":      "2020010211153423123456",
		"coin":          "eth",
		"chain":         "eth",
		"address":       "this is test address",
		"txid":          "this is txid",
		"total":         "5",
		"amount":        "10.0089",
		"fee":           "0",
		"status":        "0",
		"confirm_count": "5",
		"time":          "1650011196",
		"type":          "1",
	}
	err, sign := signature.ApiSign(data, platformPrivateKey)
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
	err = signature.ApiVerifySign(signature.ParseJsonToClassMap(string(resBase.Data)), shopPublicKey, resBase.Sign)
	if err != nil {
		panic(err)
	}
}
