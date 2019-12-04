package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
	"strconv"
)

const (
	ServerURL string = ""
	SandboxKey string = ""
	OrganisationCode string = ""
)

func EncodeValue(v string) string {
	data := []byte(v)
	return base64.StdEncoding.EncodeToString(data)
}

func DecodeValue(v string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(v)
}

func Encrypt(plainText, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

  blockSize := block.BlockSize()
  origData := PKCS5Padding(plainText, blockSize)
	mode := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(origData))
	mode.CryptBlocks(cipherText, origData)

	return cipherText, nil
}

func PKCS5Padding(src []byte, blockSize int) []byte {
  padding := blockSize - len(src)%blockSize
  padtext := bytes.Repeat([]byte{byte(padding)}, padding)
  return append(src, padtext...)
}

func Decrypt(encrypted string, key, iv []byte) ([]byte, error) {
	cipherText, _ := hex.DecodeString(encrypted)
	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	mode.CryptBlocks(origData, cipherText)
	origData = PKCS5UnPadding(origData)

	return origData, nil
}

func PKCS5UnPadding(src []byte) []byte {
  length := len(src)
  unpadding := int(src[length - 1])
  return src[:(length - unpadding)]
}

func GetCredentials(URLPath, organisationCode string) map[string]string {
	client := &http.Client{}
	request, err := http.NewRequest("POST", fmt.Sprintf("%s/%s", ServerURL, URLPath), nil)

	// Headers
	request.Header.Set("OrganisationCode", organisationCode)
	request.Header.Set("Sandbox-Key", SandboxKey)

	response, err := client.Do(request)

	if err != nil {
		panic(err)
	}

	defer response.Body.Close()

	requiredCredentials := map[string]string{
		"Aes_key": "",
		"Code": "",
		"Email": "",
		"Ivkey": "",
		"Name": "",
		"Password": "",
		"Responsecode": "",
	}

	for paramName, _ := range requiredCredentials {
		requiredCredentials[paramName] = response.Header.Get(paramName)
	}

	return requiredCredentials
}

func DoRequest(URLPath, organisationCode, signature, authorization string, credentials map[string]string, payload map[string]string) (string, error) {
	jsonValue, _ := json.Marshal(payload)
	encryptedJSONValue, err := Encrypt(jsonValue, []byte(credentials["Aes_key"]), []byte(credentials["Ivkey"]))
	hexJSONValue := hex.EncodeToString(encryptedJSONValue)

	fmt.Println("Sending: ", hexJSONValue)

	if err != nil {
		return "", err
	}

	client := &http.Client{}
	request, err := http.NewRequest("POST", fmt.Sprintf("%s/%s", ServerURL, URLPath), bytes.NewBuffer([]byte(hexJSONValue)))

	// Headers
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Length", strconv.Itoa(len(hexJSONValue)))
	request.Header.Set("OrganisationCode", organisationCode)
	request.Header.Set("Sandbox-Key", SandboxKey)
	request.Header.Set("Authorization", authorization)
	request.Header.Set("SIGNATURE", signature)
	request.Header.Set("SIGNATURE_METH", "SHA256")

	response, err := client.Do(request)

	if err != nil {
		return "", err
	}

	data, err := ioutil.ReadAll(response.Body)

	fmt.Println("Response Status: ", response.Status)
	return string(data), err
}

func main() {
	credentials := GetCredentials("nibss/bvnr/Reset", EncodeValue(OrganisationCode))
	fmt.Println("Received Credentials: ", credentials)

	// Authorization base64
	authorizationString := fmt.Sprintf("%s:%s", credentials["Code"], credentials["Password"])
	authorization := EncodeValue(authorizationString)
	fmt.Println("authorization: ", authorization)

	// Signature sha256
	today := time.Now().Format("20060102") /*YYYYMMDD format*/
	signatureString := fmt.Sprintf("%s%s%s", credentials["Code"], today, credentials["Password"])
	h := sha256.New()
	h.Write([]byte(signatureString))
	signature := hex.EncodeToString(h.Sum(nil))
	fmt.Println("signature: ", signature)

	// Make Request
	payload := map[string]string{
		"BVN": "12345678901",
	}

	fmt.Println("Sending Payload: ", payload)

	response, err := DoRequest("nibss/bvnr/VerifySingleBVN", EncodeValue(OrganisationCode), string(signature), authorization, credentials, payload)

	if err != nil {
		panic(err)
	}

	fmt.Println("Received: ", response)

	plainText, err := Decrypt(response, []byte(credentials["Aes_key"]), []byte(credentials["Ivkey"]))

	if err != nil {
		panic(err)
	}

	fmt.Println("Parsed Response: ", string(plainText))
}
