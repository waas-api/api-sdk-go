package shop_client

import (
	"context"
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"testing"
	"time"
)

var (
	testClient Client
)

func init() {
	bs, err := os.ReadFile("../config.yaml")
	if err != nil {
		panic(err)
	}
	var it struct {
		ShopClientConfig ClientConfig `json:"shop_client_config" yaml:"shop_client_config"`
	}
	err = yaml.Unmarshal(bs, &it)
	if err != nil {
		panic(err)
	}
	testClient = NewClient(it.ShopClientConfig)
}

func Test_client_Post(t *testing.T) {
	params := AddressGetBatchRequest{
		Coin: "ada",
	}
	res := AddressGetBatchResponse{}
	err := testClient.Post(context.TODO(), "/address/getBatch", params, &res)
	resBs, _ := json.MarshalIndent(res, "", "\t")
	t.Log("error:", err)
	t.Log("response:\n", string(resBs))
}

func Test_client_AddressGetBatch(t *testing.T) {
	params := AddressGetBatchRequest{
		Coin: "aca",
	}
	res, err := testClient.AddressGetBatch(context.TODO(), params)
	resBs, _ := json.MarshalIndent(res, "", "\t")
	t.Log("error:", err)
	t.Log("response:\n", string(resBs))
}

func Test_client_AddressSyncStatus(t *testing.T) {
	params := AddressSyncStatusRequest{
		Coin:    "trx",
		Address: "TQDGW4EEs4KvAKGKYvGuJawNJDvVU1wDTd",
		UserId:  "6868515",
	}
	res, err := testClient.AddressSyncStatus(context.TODO(), params)
	resBs, _ := json.MarshalIndent(res, "", "\t")
	t.Log("error:", err)
	t.Log("response:\n", string(resBs))
}

func Test_client_AddressSyncBatchStatus(t *testing.T) {
	var params = AddressSyncBatchStatusRequest{
		AddressList: []AddressSyncStatusRequest{
			{
				Coin:    "trx",
				Address: "TQDGW4EEs4KvAKGKYvGuJawNJDvVU1wDTd",
				UserId:  "6868515",
			},
			{
				Coin:    "trx",
				Address: "TQDGW4EEs4KvAKGKYvGuJawNJDvVU1wDTdXX",
				UserId:  "6868516",
			},
		},
	}
	res, err := testClient.AddressSyncBatchStatus(context.TODO(), params)
	resBs, _ := json.MarshalIndent(res, "", "\t")
	t.Log("error:", err)
	t.Log("response:\n", string(resBs))
}

func Test_client_TransferSubmit(t *testing.T) {
	var params = TransferSubmitRequest{
		UserId:  "666",
		Coin:    "trx",
		Amount:  "0.01",
		Address: "TR8HJHjNUN4mvbRZ1BfircAfHEXDHhfvNb",
		TradeId: fmt.Sprintf("%s%d", "20220101", time.Now().Unix()),
	}
	res, err := testClient.TransferSubmit(context.TODO(), params)
	resBs, _ := json.MarshalIndent(res, "", "\t")
	t.Log("error:", err)
	t.Log("response:\n", string(resBs))
}
