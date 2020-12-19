package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	shadowsocksr "github.com/mzz2017/shadowsocksR"
	"github.com/mzz2017/shadowsocksR/client"
	"github.com/mzz2017/shadowsocksR/tools/leakybuf"
	"github.com/mzz2017/shadowsocksR/tools/socks"
	"github.com/nadoo/glider/proxy"
)

var (
	readTimeout = 600 * time.Second
)

// SSInfo fields that shadowsocks/shadowsocksr used only
type SSInfo struct {
	SSRInfo
	EncryptMethod   string
	EncryptPassword string
}

// SSRInfo fields that shadowsocksr used only
type SSRInfo struct {
	Obfs          string
	ObfsParam     string
	ObfsData      interface{}
	Protocol      string
	ProtocolParam string
	ProtocolData  interface{}
}

// BackendInfo all fields that a backend used
type BackendInfo struct {
	SSInfo
	Address string
	Type    string
}
type Params struct {
	Method, Passwd, Address, Port, Obfs, ObfsParam, Protocol, ProtocolParam string
}

func convertDialerURL(params Params) (s string, err error) {
	u, err := url.Parse(fmt.Sprintf(
		"ssr://%v:%v@%v:%v",
		params.Method,
		params.Passwd,
		params.Address,
		params.Port,
	))
	if err != nil {
		return
	}
	q := u.Query()
	if len(strings.TrimSpace(params.Obfs)) <= 0 {
		params.Obfs = "plain"
	}
	if len(strings.TrimSpace(params.Protocol)) <= 0 {
		params.Protocol = "origin"
	}
	q.Set("obfs", params.Obfs)
	q.Set("obfs_param", params.ObfsParam)
	q.Set("protocol", params.Protocol)
	q.Set("protocol_param", params.ProtocolParam)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func main() {
	bi := &BackendInfo{
		Address: "sf4.kingss.me:27407",
		Type:    "ssr",
		SSInfo: SSInfo{
			EncryptMethod:   "none",
			EncryptPassword: "zzJB74cwSR",
			SSRInfo: SSRInfo{
				Protocol:      "origin",
				ProtocolParam: "",
				Obfs:          "plain",
				ObfsParam:     "",
			},
		},
	}
	bi.Listen()
}

func (bi *BackendInfo) Listen() {
	//listener, err := net.ListenTCP("tcp", "0.0.0.0:1080")
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: 1080,
		Zone: "",
	})
	if err != nil {
		panic(err)
	}
	for {
		localConn, err := listener.AcceptTCP()
		if err != nil {
			continue
		}
		go bi.Handle(localConn)
	}
}

func (bi *BackendInfo) Handle(src net.Conn) {
	//直接访问google
	rawaddr := socks.ParseAddr("sf4.kingss.me:27407")
	//	rawaddr := socks.ParseAddr("www.google.com")

	log.Println("=====", rawaddr)
	dst, err := bi.DialSSRConn(rawaddr)
	if err != nil {
		panic("ggg=" + err.Error())
	}

	go bi.Pipe(src, dst)
	bi.Pipe(dst, src)
	src.Close()
	dst.Close()
}

func (bi *BackendInfo) DialSSRConn(rawaddr socks.Addr) (net.Conn, error) {
	u := &url.URL{
		Scheme: bi.Type,
		Host:   bi.Address,
	}
	v := u.Query()
	v.Set("encrypt-method", bi.EncryptMethod)
	v.Set("encrypt-key", bi.EncryptPassword)
	v.Set("obfs", bi.Obfs)
	v.Set("obfs-param", bi.ObfsParam)
	v.Set("protocol", bi.Protocol)
	v.Set("protocol-param", bi.ProtocolParam)
	u.RawQuery = v.Encode()
	ssrconn, err := shadowsocksr.NewSSRClient(u)
	if err != nil {
		return nil, fmt.Errorf("connecting to SSR server failed :%v", err)
	}

	if bi.ObfsData == nil {
		bi.ObfsData = ssrconn.IObfs.GetData()
	}
	ssrconn.IObfs.SetData(bi.ObfsData)

	if bi.ProtocolData == nil {
		bi.ProtocolData = ssrconn.IProtocol.GetData()
	}
	ssrconn.IProtocol.SetData(bi.ProtocolData)

	if _, err := ssrconn.Write(rawaddr); err != nil {
		ssrconn.Close()
		return nil, err
	}
	return ssrconn, nil
}

// PipeThenClose copies data from src to dst, closes dst when done.
func (bi *BackendInfo) Pipe(src, dst net.Conn) error {
	buf := leakybuf.GlobalLeakyBuf.Get()
	for {
		src.SetReadDeadline(time.Now().Add(readTimeout))
		n, err := src.Read(buf)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			if _, err := dst.Write(buf[0:n]); err != nil {
				break
			}
		}
		if err != nil {
			// Always "use of closed network connection", but no easy way to
			// identify this specific error. So just leave the error along for now.
			// More info here: https://code.google.com/p/go/issues/detail?id=4373
			break
		}
	}
	leakybuf.GlobalLeakyBuf.Put(buf)
	dst.Close()
	return nil
}
func mainw() {
	/***
	bi := &BackendInfo{
		Address: "sf4.kingss.me:27407",
		Type:    "ssr",
		SSInfo: SSInfo{
			EncryptMethod:   "none",
			EncryptPassword: "zzJB74cwSR",
			SSRInfo: SSRInfo{
				Protocol:      "origin",
				ProtocolParam: "",
				Obfs:          "plain",
				ObfsParam:     "",
			},
		},
	}
	bi.Listen()


	*/
	s, err := convertDialerURL(Params{
		Method:        "none",
		Passwd:        "zzJB74cwSR",
		Address:       "sf1.kingss.me",
		Port:          "27407",
		Obfs:          "plain",
		ObfsParam:     "",
		Protocol:      "origin",
		ProtocolParam: "",
	})
	if err != nil {
		log.Fatal(err)
	}
	dia, err := client.NewSSRDialer(s, proxy.Default)
	if err != nil {
		log.Fatal(err)
	}
	c := http.Client{
		Transport: &http.Transport{Dial: dia.Dial},
	}
	resp, err := c.Get("http://facebook.com")
	if err != nil {
		log.Fatal(err)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	defer resp.Body.Close()
	log.Println(buf.String())
}
