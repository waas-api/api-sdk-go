package example

import (
	"github.com/waas-api/api-sdk-go/callback_server"
	"github.com/waas-api/api-sdk-go/crypto"
	"log"
	"net/http"
	"testing"
	"time"
)

var (
	privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCY7RWlhM51ArHr
QIuWd1tqABES34/3gqSegp+PW1nu7lL0w9z/+dB3GZP243LO54v2K/QHrDHuEEPc
VD4WhaTtrho55YRkXFKQNCmE3W/pKZYnU+BOEBEF7wZBt3X+82xNafKvHscfNl1m
y2to+P74nLGE6kQNZrA+0RGxib9k9JxV1TsNVxLYSlf4TJ4Ikb82qtXMxEXDaEC7
mFNtoefJJShw+BMwqmRfOhDP8LG4+10/Kx2ZT0lxyHdF/NyWOazzDzcwxT6Hzzzh
sP2yNW9tLdlk+SnMVsZEqOBNKzraYCRBhsis0+zmWejQQ5Q3Nu3CHg088+WLci+9
ee7G3zLzAgMBAAECggEAQCtb5fRwXZEf70NKT30OEtCsWWsOEiHzyb+uDI2ckzHW
BXcaiR7eZtuIxxRx3Hg0truCzqVm3ipdD1saIoE5z7I6twikISjMTE5XDbWNfB1D
MIV1ncwIGKFP0suU68JhM6q9dtZHX8WEM9ov3AB/nPrDUq6ql6T7V6CK+CCA+28z
DG6Bh8jgGMCGyPtvi7ku09pJUGLwRBfRGE2wpcZ4nvSLwbv9Eyaf2ZIyZw6MH6lF
IyI9uVY5ePWh/vVQdbXFmSH2GAuxzxz3T9IvMwUyXiK4t7hVWHJlf9/UQpfbFTXc
4V+/Tmn1gQuLmL4oTs1bRg28AhIsunc9yxlr3wfmAQKBgQDHLm4LG+VUIgGJhxR6
+KmhXJ3S84PdNhEbnNmRJd2ZQlH38YAjndf2FLTH9KoyWw/hfJp3GTHv716W+T1u
qBUhUw7ELugzNY0scxG0xBt+9hJAku+MwgXx53ZnDfV6iRKbc8x/RNRs+OQi8nCa
PO3pdKNrMOHtohuYp0+jDAhiMwKBgQDEjMiBPvw6ZWa2Jm2Q9FhSwUc86ZiT+o3M
AyoQtIFVXWhCM4I5Yk5JzDIi05iJb/dtyulp9UK+/HIKaJtj2Shsp5CZMW9UISea
klrtk/xS0A4qUUOxNxOFNzQl466RULxLCR0kmLqJ6ou8hHpOkdvlGqRbE5JVVOCM
akoa8iysQQKBgBT5QaMv080xK4JE1BZC2vHf48qT093WVKTYtlw/ZX8+6Yy3RGv7
sgL6mTK5A7b7ucdfrJA/+e8vAIHbSum9D0SMD3D/E3pY+D2m/EVRpSeQV8mu70Se
JawcWG5vnNrDVk9COVVpdQjoiHVZnBvRsKe1nYOrCQ9R06AWdh9QJA3bAoGBAIvj
d0Elxvb4/KVfrFOi1MnxbfZYe5O2m/07s1C4Z+SN2opjhqe44+d6QaSv3LzUx9GI
vaAAQ0US/0eRNCdYg4DxseSWXpoODtXgnH7C+K8oDSzpMbiLboU9yQu+hJxATgNJ
tUg6u2k1WccOss4A2fSxhZCc2WWKR1covx12h30BAoGBALZ8IpYY5IJuFXM0aYg5
QbOLlDG0Z13bIpKmgk5IHq53uEkR2+ttSN7i2W3fJhlpUpr4HFXEP5Uk3Q7KE4De
ziVkAkNnZ4c8TISG2SANqaSZggQWXnZNu3am7P/C/19EHOGJigM/wsbjw5KXMqMY
ny5QBi2nWF73omosGLjTrSZ2
-----END PRIVATE KEY-----
`

	// provide by platform
	platformPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0NwyEfQupjAtS7zIeMuR
995t5fzW9FRm9i3+WKQlfLf81wb2dxUyZh2kalCZkkXHbJyyv2XDhMidf1l3kZo/
gCXS+RHmsfinCRE6Y4rkFPLhYvq0tGhkoVDFVhPHZGdRkaUBRWlj8pN/BuyMYLMY
uGrYAQb2J/c4UG0nCB/VuqQ+WsQoNMHxIU/HGehsShHI99maezheP0F6QNIPUtxe
GDKQ52Ks1dWwtIq433MiwRDWaGfRXMVzK+D99BET09e41lJVqvNijhRHwXo6bxjV
kJRYmCGShTkYITeDVhd6NpV/mhPrRSQcwEXjJSObHcbh9UhIZjZGAw56Qfqz66wk
lwIDAQAB
-----END PUBLIC KEY-----
`
)

var (
	riskPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDP1ZvDgmtRszLy
s7d933C+Qv+9mC1IiJM45IBqMW9haNcOlxY/rB9ewKBY7pC7njeo1LMQxIzgSaeh
MdNsTXLfsO2o3pkn7Vzof0kP8W4pKPRarnNoV7qNvRh0Lbwb2bzzwul1kUovHv7M
MO6wIQmC3QMWJMz3l8WP5wz7aAnpI9DGzaei4PO8/lyj0vBAGuR0mdIXE5x62I/2
j5nHl7pZsuLIia/pOpc7FHK3F288SmICpmiRjz4WLLqCxuKFZW7hEYzzoddf4mxP
ydXB71T8Y/sN7rifz3hPuavHh6pYbyDvMjO0RJCJ1cPnEE7OgDgrFWAG5suEPL2F
Te3ZoJZxAgMBAAECggEAa2Ad2HWSAqTFhrSo8UQ2WGX/ALIVeyrsfPE5EyQ1OitT
KHuQiBbiIi786NVgOz5z3Sr+1IPnkJ0dGN/ILmUZG06qiptunz03yfqxAaanVmaN
UChfAaKJhF8UujlCvVTSFVI3EYGdxRiLZW1GdAKtikmrJY6fwq9L55vkjiLjM+pZ
aDzs9ZNoGDKJPvfb2U694B43U6IB3krwZD8wUMi8CP/3MON5hjdIQ820zfk9j8lg
x5sWRkRzIhe2cKe8TRC1oPRt2io6Uxv1HnWFDpLQ/1eEkRTVTAEEpAKfgshMyOY2
BP0FSDZTssBzAYDdNHqDAyNXFbD6eYQRDMUwhZhGAQKBgQDzqOQPlVUY9uAs9E76
XM/uXVwigaqQ6NUxjXXs+tGSnwcu5nk2GlNgYU5IJUgd8/G2fGxn2luPO2G1/X+6
Bj6bRGFu+YS8NkE7fuFze6nu2TKe3wunQJldScqSOpELTWiTcDe8FlMqHnGncJ44
JxkXEKCgysoInGBE3zyH+k0KoQKBgQDaXDu9fXNQmKhmu1MYveKfD1L7L1R0FKB5
8glY2GjhHwZW9lwn7W1t6kOroHCIHPKxlKNuWBT7uIs/Agd/Mo+fA6w3mn/oEHzr
gsrqabeIMKHIJXiGt1wlfp/fyIdMwAumN9yMGOoLS+oa3DMOfFa/vQpEXVOJsIzU
Vt/rBtNJ0QKBgBp04C6A/Hh1denrrReqNDmhkXt9sNODNILo5UESCudstQ72n3qs
aRkx95oF0krOThSOdgbgwshOnlFwcQn1255oUlwGY8875OFc6YXsi4sPsltlxJIo
hX6HoKM4EL+1bAF2UdbuZaFRJO4VYFighizm9UoAOuescxeHVb8+AleBAoGBAKWo
KW5FWRGA7ukZHh58GAwhvQtwybpS17gL5glwDIkVV2Lr/dgQqN8lRXdT/WtVwszz
/dS9oBWj2IfRi0x1WD4DtEhuvrCYqZymGjkiQKlic6n6u2hAfPi5CqLkZ7jTTUMp
x/jFAfHWAuGjwlwv+kP2L27T+odP2FdTHQcZo3uxAoGAT1HFdzSQLpPAtJyhPqff
nhks+XHdsmGic35CAQyyiEUIz4MoxKwnodWu1hDfpdPexcAhbwWSW04TtKXC5eur
+H1E7F2KcMJ2IeTzFB691bzeseSrG6QIkKOFC/hSI5ac+lem98Pc3i3MRDx3xRvB
sAy4uAWdzJAA70TWEOsVIUw=
-----END PRIVATE KEY-----
`

	// provide by platform
	riskPlatformPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6YDzI7HOT14i2xWsSfBj
ZQKGt3zzMU7UDFNkYwa539wFM6FRnkFd6HcTjqCWehivLTbQSbV1wTd9Ub7zXSEE
C0OKcCqHCYXdWYW48jAwtvRKUjGJ0PKxxZS2XUUWpubbQAXLRUx7DmtbCyDDe+cw
lKxGI5P6ppSSNGmRpbOztSAyUsL1njv5zw2u91LRo6stM06FCV3x+kJsWYmcs0kz
chAt89QwfiUK5G6T8myIyFHEKozsiU2brGd5XvxpdX4jJ5RAP0jGUr3i1n7p4dT2
SRFL0WENHqgkoKaxPwAtTSg7j4YotMXfSvkNk7CJXYvq63GTX1UWL72OsmtKdvkY
DwIDAQAB
-----END PUBLIC KEY-----
`
)

func Test_CallbackServer(t *testing.T) {

	http.HandleFunc("/callback/deposit", callback_server.NewHandlerDeposit(func(request callback_server.DepositCallbackRequest) callback_server.DepositCallbackResponse {

		log.Println("get deposit callback", request)

		ret := callback_server.DepositCallbackResponse{}

		// check request sign
		if err := crypto.CallbackServerVerifyRequestSign(request, platformPublicKey); err != nil {
			ret.Status = 500
			log.Println("verify sign fail", err)
			return ret
		}

		// check info according to your needs
		{
			var localAmount = "10.0089"
			if localAmount != request.Data.Amount {
				ret.Status = 500
				ret.Data.SuccessData = "amount invalid"
				return ret
			}
		}

		// return success after all check is OK
		ret.Status = 200
		ret.Data.SuccessData = "success"

		// generate sign for response
		if sign, err := crypto.CallbackServerGenResponseSignOnly(ret.Data, privateKey); err != nil {
			ret.Status = 500
			log.Println("gen sign fail", err)
			return ret
		} else {
			ret.Sign = sign
		}

		return ret
	}))

	http.HandleFunc("/callback/withdraw", callback_server.NewHandlerWithdraw(func(request callback_server.WithdrawCallbackRequest) callback_server.WithdrawCallbackResponse {

		log.Println("get withdraw callback", request)

		ret := callback_server.WithdrawCallbackResponse{}

		// check request sign
		if err := crypto.CallbackServerVerifyRequestSign(request, platformPublicKey); err != nil {
			ret.Status = 500
			log.Println("verify sign fail", err)
			return ret
		}

		// check info according to your needs
		{
			var localAmount = "0.5"
			if localAmount != request.Data.Amount {
				ret.Status = 500
				ret.Data.SuccessData = "amount invalid"
				return ret
			}
			var localTradeId = "12345678"
			if localTradeId != request.Data.TradeId {
				ret.Status = 500
				ret.Data.SuccessData = "unknown trade_id"
				return ret
			}
		}

		// return success after all check is OK
		ret.Status = 200
		ret.Data.SuccessData = "success"

		// generate sign for response
		if sign, err := crypto.CallbackServerGenResponseSignOnly(ret.Data, privateKey); err != nil {
			ret.Status = 500
			log.Println("gen sign fail", err)
			return ret
		} else {
			ret.Sign = sign
		}

		return ret
	}))

	http.HandleFunc("/callback/withdraw/risk", callback_server.NewHandlerWithdrawRisk(func(request callback_server.WithdrawRiskCallbackRequest) callback_server.WithdrawRiskCallbackResponse {

		log.Println("get withdraw risk callback", request)

		ret := callback_server.WithdrawRiskCallbackResponse{}

		// check request sign
		if err := crypto.CallbackServerVerifyRequestSign(request, riskPlatformPublicKey); err != nil {
			ret.Status = 5400
			ret.Data.StatusCode = 5400
			log.Println("verify sign fail", err)
			return ret
		}

		// check info according to your needs
		{
			var localAmount = "2.00000000"
			if localAmount != request.Data.Amount {
				ret.Status = 5002
				ret.Data.StatusCode = 5002
				return ret
			}
		}

		// return success after all check is OK
		ret.Status = 200
		ret.Data.StatusCode = 200
		ret.Data.OrderId = request.Data.OrderId
		ret.Data.Timestamp = time.Now().Unix()

		// generate sign for response
		if sign, err := crypto.CallbackServerGenResponseSignOnly(ret.Data, riskPrivateKey); err != nil {
			ret.Status = 500
			log.Println("gen sign fail", err)
			return ret
		} else {
			ret.Sign = sign
		}

		return ret
	}))

	log.Println("Starting server at port 8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
