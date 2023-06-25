package client

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

var (
	testClient Client
)

func init() {
	var conf = Config{
		AppId:      "asdfau9imt86qky9",
		Version:    "1.0",
		KeyVersion: "admin",
		BaseUrl:    "http://api.xxx.com/shopapi",
		PrivateKey: `-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----`,
		PlatformPublicKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0NwyEfQupjAtS7zIeMuR
995t5fzW9FRm9i3+WKQlfLf81wb2dxUyZh2kalCZkkXHbJyyv2XDhMidf1l3kZo/
gCXS+RHmsfinCRE6Y4rkFPLhYvq0tGhkoVDFVhPHZGdRkaUBRWlj8pN/BuyMYLMY
uGrYAQb2J/c4UG0nCB/VuqQ+WsQoNMHxIU/HGehsShHI99maezheP0F6QNIPUtxe
GDKQ52Ks1dWwtIq433MiwRDWaGfRXMVzK+D99BET09e41lJVqvNijhRHwXo6bxjV
kJRYmCGShTkYITeDVhd6NpV/mhPrRSQcwEXjJSObHcbh9UhIZjZGAw56Qfqz66wk
lwIDAQAB
-----END PUBLIC KEY-----`,
	}

	testClient = NewClient(conf)
}

func Test_client_CoinList(t *testing.T) {
	params := CoinListRequest{
		Coin: "trx",
	}
	// get shop support coins
	res, err := testClient.CoinList(context.TODO(), params)
	resBs, _ := json.MarshalIndent(res, "", "\t")
	t.Log("error:", err)
	t.Log("response:\n", string(resBs))
}

func Test_client_AddressGetBatch(t *testing.T) {
	params := AddressGetBatchRequest{
		Coin: "trx",
	}
	res, err := testClient.AddressGetBatch(context.TODO(), params)
	resBs, _ := json.MarshalIndent(res, "", "\t")
	t.Log("error:", err)
	t.Log("response:\n", string(resBs))
}

func Test_client_AddressSyncStatus(t *testing.T) {
	params := AddressSyncStatusRequest{
		Coin:    "trx",
		Address: "TQDGW4EEs4KvAKGKYvGuJawNJDvVU1wDTd0",
		UserId:  "68685150",
	}
	res, err := testClient.AddressSyncStatus(context.TODO(), params)
	resBs, _ := json.MarshalIndent(res, "", "\t")
	t.Log("error:", err)
	t.Log("response:\n", string(resBs))
}

func Test_client_AddressList(t *testing.T) {
	params := AddressListRequest{
		Coin:   "trx",
		IsUsed: 2,
	}
	res, err := testClient.AddressList(context.TODO(), params)
	resBs, _ := json.MarshalIndent(res, "", "\t")
	t.Log("error:", err)
	t.Log("response:\n", string(resBs))
}

func Test_client_Transfer(t *testing.T) {
	var params = TransferRequest{
		UserId:  "666",
		Coin:    "trx",
		Amount:  "0.01",
		Address: "TR8HJHjNUN4mvbRZ1BfircAfHEXDHhfvNb",
		TradeId: fmt.Sprintf("%s%d", "20220101", time.Now().Unix()),
	}
	res, err := testClient.Transfer(context.TODO(), params)
	resBs, _ := json.MarshalIndent(res, "", "\t")
	t.Log("error:", err)
	t.Log("response:\n", string(resBs))
}
