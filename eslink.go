package easySecurityLink

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/gob"
	"io"
	"log"
	"net"
)

//信息载体
type Message struct {
	T    string //类型
	Data []byte
	Add  int //尾部多出来的字符数，用于适应AES加密算法的BlockSize
}

//安全连接载体
type ESLink struct {
	C            net.Conn
	PrivKey      *rsa.PrivateKey
	RemotePubKey *rsa.PublicKey
	AesKey       []byte
}

//接收加密的信息，data的Add字段为0
func (s *ESLink) Read() (data *Message, err error) {
	decoder := gob.NewDecoder(s.C)
	buf := Message{}
	err = decoder.Decode(&buf)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(s.AesKey)
	if err != nil {
		return nil, err
	}
	var n int = 0
	length := len(buf.Data)
	bs := block.BlockSize()
	res := Message{T: buf.T, Data: make([]byte, length), Add: 0}
	for {
		block.Decrypt(res.Data[n:], buf.Data[n:])
		n += bs
		if n >= length {
			break
		}
	}
	res.Data = res.Data[:length-buf.Add]
	return &res, nil
}

//加密信息然后发送
func (s *ESLink) Write(typ string, data []byte) (err error) {
	encoder := gob.NewEncoder(s.C)
	block, err := aes.NewCipher(s.AesKey)
	if err != nil {
		return err
	}
	var n int = 0
	length := len(data)
	bs := block.BlockSize()
	add := bs - length%bs
	length += add
	buf := bytes.NewBuffer(data)
	buf.Write(make([]byte, add))
	data = buf.Bytes()
	res := Message{T: typ, Data: make([]byte, length), Add: add}
	for {
		block.Encrypt(res.Data[n:], data[n:])
		n += bs
		if n >= length {
			break
		}
	}
	err = encoder.Encode(res)
	return err
}

//关闭连接
func (s *ESLink) Close() error {
	return s.C.Close()
}

//把指定的连接升级为安全连接（服务端）
func Upgrade(c net.Conn) (*ESLink, error) {
	decoder := gob.NewDecoder(c)
	encoder := gob.NewEncoder(c)

	//接收来自客户端的公钥
	remotePubKey := rsa.PublicKey{}
	err := decoder.Decode(&remotePubKey)
	if err != nil {
		c.Close()
		return nil, err
	}
	//向客户端发送加密的AES密码（32字节），后32位是label
	var rdata [64]byte
	_, err = io.ReadFull(rand.Reader, rdata[:])
	if err != nil {
		c.Close()
		return nil, err
	}
	aesKey := rdata[:32]
	label := rdata[32:]
	keyCrypt, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &remotePubKey, aesKey, label)
	if err != nil {
		c.Close()
		return nil, err
	}
	data := bytes.NewBuffer(keyCrypt)
	//log.Println(len(keyCrypt))
	data.Write(label)
	reply1 := Message{T: "Key", Data: data.Bytes(), Add: 0}
	err = encoder.Encode(reply1)
	if err != nil {
		c.Close()
		return nil, err
	}

	link := &ESLink{C: c, PrivKey: nil, RemotePubKey: &remotePubKey, AesKey: aesKey}

	return link, nil
}

//接受连接（服务端）
func Accept(listener net.Listener) (*ESLink, error) {
	c, err := listener.Accept()
	if err != nil {
		return nil, err
	}

	return Upgrade(c)
}

//建立连接（客户端）
func Dial(addr string) (*ESLink, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	decoder := gob.NewDecoder(c)
	encoder := gob.NewEncoder(c)

	//生成私钥
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		c.Close()
		return nil, err
	}
	//发送公钥
	err = encoder.Encode(privKey.Public())
	if err != nil {
		c.Close()
		return nil, err
	}
	//接收AES密码
	reply1 := Message{}
	err = decoder.Decode(&reply1)
	if err != nil {
		c.Close()
		return nil, err
	}
	if reply1.T != "Key" {
		c.Close()
		return nil, err
	}
	aesKey := reply1.Data[:256]
	label := reply1.Data[256:]
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, aesKey, label)
	if err != nil {
		c.Close()
		log.Println(err.Error())
		return nil, err
	}

	link := &ESLink{C: c, PrivKey: privKey, RemotePubKey: nil, AesKey: key}

	return link, nil
}
