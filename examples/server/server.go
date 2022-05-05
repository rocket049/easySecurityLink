package main

import (
	"fmt"
	"net"

	"gitee.com/rocket049/easySecurityLink"
)

func main() {
	l, err := net.Listen("tcp", "0.0.0.0:9000")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	for {
		c, err := easySecurityLink.Accept(l)
		if err != nil {
			continue
		}
		go func(conn *easySecurityLink.ESLink) {
			for {
				m, err := conn.Read()
				if err != nil {
					break
				}
				fmt.Println(m.T, string(m.Data))
				conn.Write("S", []byte("Reply:"+string(m.Data)))
			}
		}(c)
	}
}
