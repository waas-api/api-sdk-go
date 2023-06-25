package callback_server

import (
	"encoding/json"
	"io"
	"net/http"
)

type DepositCallbackRequest struct {
	Data DepositCallbackRequestData `json:"data"`
	Sign string                     `json:"sign"`
}

type DepositCallbackRequestData struct {
	Address      string `json:"address"`
	Amount       string `json:"amount"`
	Chain        string `json:"chain"`
	Coin         string `json:"coin"`
	ConfirmCount int    `json:"confirm_count"`
	Fee          string `json:"fee"`
	FromAddress  string `json:"from_address"`
	OrderId      string `json:"order_id"`
	Status       int    `json:"status"`
	Time         int    `json:"time"`
	Total        string `json:"total"`
	Txid         string `json:"txid"`
	Type         int    `json:"type"`
}

type DepositCallbackResponse struct {
	Status int `json:"status"`
	Data   struct {
		SuccessData string `json:"success_data"`
	} `json:"data"`
	Sign string `json:"sign"`
}

func NewHandlerDeposit(businessFn func(DepositCallbackRequest) DepositCallbackResponse) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		request := DepositCallbackRequest{}

		// this block can be in web server middleware or your custom controller
		{
			bs, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(400)
				w.Write([]byte(err.Error()))
				return
			}
			err = json.Unmarshal(bs, &request)
		}

		// exec your business code
		response := businessFn(request)

		// this block can be in web server middleware or your custom controller
		{
			resBytes, err := json.Marshal(response)
			if err != nil {
				w.WriteHeader(500)
				w.Write([]byte(err.Error()))
				return
			}
			w.WriteHeader(200)
			w.Write(resBytes)
		}
	}
}
