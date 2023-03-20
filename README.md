# api-sdk-go

## Shop Client Example
```go
func main() {
    cf := shop_client.ClientConfig{
        AppId:             "asdf",
        Version:           "1.0",
        KeyVersion:        "admin",
        PrivateKey:        "xxx",
        PlatformPublicKey: "xxx",
        BaseUrl:           "https://api.xxx.com",
    }
    c := shop_client.NewClient(cf)
    
    params := shop_client.AddressGetBatchRequest{
        Coin: "trx",
    }
    res, err := c.AddressGetBatch(context.TODO(), params)
    resBs, _ := json.MarshalIndent(res, "", "\t")
    fmt.Println("error:", err)
    fmt.Println("response:\n", string(resBs))
}
```

> See more example in file `shop_client/client_test.go`.

## Callback Server Example
> See more example in file `callback_server/server_test.go`.