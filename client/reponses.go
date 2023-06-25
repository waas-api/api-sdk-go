package client

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

type CoinListResponse struct {
	Response
	Data *CoinListData `json:"data"`
}

func (rcv *CoinListResponse) UnmarshalJSON(bytes []byte) error {
	var r Response
	err := json.Unmarshal(bytes, &r)
	if err != nil {
		return err
	}
	rcv.Response = r
	if len(r.Data) == 2 && r.Data[0] == '[' && r.Data[len(r.Data)-1] == ']' {
		return nil
	}
	var data CoinListData
	err = json.Unmarshal(r.Data, &data)
	if err != nil {
		return err
	}
	rcv.Data = &data
	return nil
}

type CoinListData struct {
	Count   int            `json:"count"`
	List    []CoinListItem `json:"list"`
	MaxPage int            `json:"max_page"`
	Page    int            `json:"page"`
}

type CoinListItem struct {
	Chain                string `json:"chain"`
	Coin                 string `json:"coin"`
	ConfirmCount         string `json:"confirm_count"`
	MinTransferInAmount  string `json:"min_transfer_in_amount"`
	MinTransferOutAmount string `json:"min_transfer_out_amount"`
	OpenAddress          string `json:"open_address"`
	OpenIn               int    `json:"open_in"`
	OpenOut              int    `json:"open_out"`
	Status               string `json:"status"`
}

type AddressGetBatchResponse struct {
	Response
	Data []string `json:"data"`
}

type AddressSyncStatusResponseDataItem struct {
	Address string `json:"address"`
	Coin    string `json:"coin"`
	// fail part
	Msg         string `json:"msg,omitempty"`
	Status      string `json:"status,omitempty"`
	OldAddress  string `json:"old_address,omitempty"`
	OwnerUserId string `json:"owner_user_id,omitempty"`
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
	if len(r.Data) == 2 && r.Data[0] == '[' && r.Data[len(r.Data)-1] == ']' {
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

type AddressListResponse struct {
	Response
	Data *AddressListData `json:"data"`
}

func (rcv *AddressListResponse) UnmarshalJSON(bytes []byte) error {
	var r Response
	err := json.Unmarshal(bytes, &r)
	if err != nil {
		return err
	}
	rcv.Response = r
	if len(r.Data) == 2 && r.Data[0] == '[' && r.Data[len(r.Data)-1] == ']' {
		return nil
	}
	var data AddressListData
	err = json.Unmarshal(r.Data, &data)
	if err != nil {
		return err
	}
	rcv.Data = &data
	return nil
}

type AddressListData struct {
	Count   int               `json:"count"`
	List    []AddressListItem `json:"list"`
	MaxPage int               `json:"max_page"`
	Page    int               `json:"page"`
}

type AddressListItem struct {
	Address string `json:"address"`
	UserId  string `json:"user_id"`
}

// transfer(withdraw)

type TransferResponseData struct {
	TradeId string `json:"trade_id"`
}

type TransferResponse struct {
	Response
	Data *TransferResponseData
}

func (rcv *TransferResponse) UnmarshalJSON(bytes []byte) error {
	var r Response
	err := json.Unmarshal(bytes, &r)
	if err != nil {
		return err
	}
	rcv.Response = r
	if len(r.Data) == 2 && r.Data[0] == '[' && r.Data[len(r.Data)-1] == ']' {
		return nil
	}
	var data TransferResponseData
	err = json.Unmarshal(r.Data, &data)
	if err != nil {
		return err
	}
	rcv.Data = &data
	return nil
}
