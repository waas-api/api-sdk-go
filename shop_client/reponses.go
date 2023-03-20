package shop_client

import (
	"encoding/json"
	"fmt"
)

type Response struct {
	Status    int             `json:"status"`
	Msg       string          `json:"msg"`
	Data      json.RawMessage `json:"data"`
	DateTime  string          `json:"date_time"`
	TimeStamp int64           `json:"time_stamp"`
	Sign      string          `json:"sign"`
}

func (rcv *Response) ApiError() error {
	if rcv.Status == 200 {
		return nil
	}
	return fmt.Errorf("API Error, code %d, %s", rcv.Status, rcv.Msg)
}

// address

type AddressGetBatchResponse struct {
	Response
	Data []string `json:"data"`
}

type AddressSyncStatusResponseDataItem struct {
	Address string `json:"address"`
	Coin    string `json:"coin"`
	// fail part
	Msg         string `json:"msg"`
	Status      string `json:"status"`
	OldAddress  string `json:"old_address"`
	OwnerUserId string `json:"owner_user_id"`
}

type AddressSyncStatusResponse struct {
	Response
	Data *AddressSyncStatusResponseDataItem `json:"data"`
}

func (rcv *AddressSyncStatusResponse) UnmarshalJSON(bytes []byte) error {
	var r Response
	err := json.Unmarshal(bytes, &r)
	if err != nil {
		return err
	}
	rcv.Response = r
	if r.Data[0] == '[' && r.Data[len(r.Data)-1] == ']' {
		return nil
	}
	var data AddressSyncStatusResponseDataItem
	err = json.Unmarshal(r.Data, &data)
	if err != nil {
		return err
	}
	rcv.Data = &data
	return nil
}

type AddressSyncBatchStatusResponse struct {
	Response
	SuccessData []AddressSyncStatusResponseDataItem `json:"success_data"`
	FailData    []AddressSyncStatusResponseDataItem `json:"fail_data"`
}

type TransferSubmitResponseData struct {
	TradeId string `json:"trade_id"`
}

// transfer(withdraw)

type TransferSubmitResponse struct {
	Response
	Data *TransferSubmitResponseData
}

func (rcv *TransferSubmitResponse) UnmarshalJSON(bytes []byte) error {
	var r Response
	err := json.Unmarshal(bytes, &r)
	if err != nil {
		return err
	}
	rcv.Response = r
	if r.Data[0] == '[' && r.Data[len(r.Data)-1] == ']' {
		return nil
	}
	var data TransferSubmitResponseData
	err = json.Unmarshal(r.Data, &data)
	if err != nil {
		return err
	}
	rcv.Data = &data
	return nil
}
