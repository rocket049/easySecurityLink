package easySecurityLink

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/gob"
	"io"
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
	if res.T == "Ctrl" && bytes.Compare([]byte("Close"), res.Data) == 0 {
		s.C.Close()
		return nil, io.EOF
	}
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
		//数据段长度不够BlockSize时必须补全，还未完善
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
	err := s.Write("Ctrl", []byte("Close"))
	if err != nil {
		return err
	}
	err = s.C.Close()
	return err
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
	//向客户端发送加密的AES密码（32字节）
	var aesKey [32]byte
	_, err = io.ReadFull(rand.Reader, aesKey[:])
	if err != nil {
		c.Close()
		return nil, err
	}
	keyCrypt, err := rsa.EncryptPKCS1v15(rand.Reader, &remotePubKey, aesKey[:])
	if err != nil {
		c.Close()
		return nil, err
	}
	reply1 := Message{T: "Key", Data: keyCrypt, Add: 0}
	err = encoder.Encode(reply1)
	if err != nil {
		c.Close()
		return nil, err
	}

	link := &ESLink{C: c, PrivKey: nil, RemotePubKey: &remotePubKey, AesKey: aesKey[:]}

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
	key, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, reply1.Data)
	if err != nil {
		c.Close()
		return nil, err
	}

	link := &ESLink{C: c, PrivKey: privKey, RemotePubKey: nil, AesKey: key}

	return link, nil
}
