package crypto

import (
	"encoding/json"
	"fmt"
)

// ShopClientGenPlatformRequestSign shop client generate sign for request body before send request to platform
//
//	@param reqBody http request body going to send, type can be []byte, string or struct.
//	@param priKey shop client rsa private key.
//	@return newReqBody if reqBody type is []byte, return newReqBody type is []byte.
//	 if reqBody type is string, return newReqBody type is string.
//	 if reqBody type is struct, return newReqBody type is map[string]interface{}.
func ShopClientGenPlatformRequestSign(reqBody interface{}, priKey string) (newReqBody interface{}, err error) {
	if bs, ok := reqBody.([]byte); ok {
		params := ParseJsonToClassMap(string(bs))
		delete(params, "sign")
		err, sign := ApiSign(params, priKey)
		if err != nil {
			return reqBody, err
		}
		newParams := make(map[string]interface{})
		if err := json.Unmarshal(bs, &newParams); err != nil {
			return reqBody, err
		}
		newParams["sign"] = sign
		bs, err = json.Marshal(newParams)
		if err != nil {
			return reqBody, err
		}
		return bs, nil
	} else if str, ok := reqBody.(string); ok {
		params := ParseJsonToClassMap(str)
		delete(params, "sign")
		err, sign := ApiSign(params, priKey)
		if err != nil {
			return reqBody, err
		}
		newParams := make(map[string]interface{})
		if err := json.Unmarshal([]byte(str), &newParams); err != nil {
			return reqBody, err
		}
		newParams["sign"] = sign
		bs, err = json.Marshal(newParams)
		if err != nil {
			return reqBody, err
		}
		return string(bs), nil
	} else {
		bs, err = json.Marshal(reqBody)
		if err != nil {
			return reqBody, err
		}
		params := ParseJsonToClassMap(string(bs))
		delete(params, "sign")
		err, sign := ApiSign(params, priKey)
		if err != nil {
			return reqBody, err
		}
		newParams := make(map[string]interface{})
		if err := json.Unmarshal(bs, &newParams); err != nil {
			return reqBody, err
		}
		newParams["sign"] = sign
		return newParams, nil
	}
}

// ShopClientVerifyPlatformResponseSign shop client verify the 'sign' of platform response
//
//	@param resBody http response body received, type can be []byte, string or struct.
//	@param pubKey rsa public key , provided by platform.
func ShopClientVerifyPlatformResponseSign(resBody interface{}, pubKey string) error {
	var (
		res     = make(map[string]interface{})
		respStr string
	)

	if bs, ok := resBody.([]byte); ok {
		if err := json.Unmarshal(bs, &res); err != nil {
			return err
		}
		respStr = string(bs)
	} else if str, ok := resBody.(string); ok {
		if err := json.Unmarshal([]byte(str), &res); err != nil {
			return err
		}
		respStr = str
	} else {
		bs, err := json.Marshal(resBody)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(bs, &res); err != nil {
			return err
		}
		respStr = string(bs)
	}

	sign, ok := res["sign"].(string)
	if !ok {
		return fmt.Errorf("no sign field in response body")
	}

	if err := ApiVerifySign(ParseJsonToClassMap(respStr), pubKey, sign); err != nil {
		return err
	}
	return nil
}
