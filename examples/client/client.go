package main

import (
	"bufio"
	"fmt"
	"os"

	"easySecurityLink"
)

func main() {
	c, err := easySecurityLink.Dial("localhost:9000")
	if err != nil {
		panic(err)
	}
	defer c.Close()
	for i := 0; i < 10; i++ {
		r := bufio.NewReader(os.Stdin)
		s, _, _ := r.ReadLine()
		c.Write("S", s)
		m, err := c.Read()
		if err != nil {
			break
		}
		fmt.Println(m.T, string(m.Data), len(m.Data), len(s))
	}
}
