# 简单安全连接：easySecurityLink

### 简单的意思，就是用法比TLS、SSL、SSH简单。

功能也比较单一，就是点对点加密连接，连接时自动生成临时密钥，不需要预先准备密钥。

### 需要注意的是，这种加密机制可以防止网络监听，但无法防止“中间人攻击”。

### 算法说明

连接时客户端生成一对2048位RSA密钥，然后把公钥发送到服务端，服务端随机生成一个256位AES密码，用接收到的RSA公钥加密此密码，发送给客户端，然后双方用此AES密码加密全部信息。

### 引用方法

`import "github.com/rocket049/easySecurityLink"`


## 用法简介

### 一、客户端

```
	c, err := easySecurityLink.Dial("host:port")
	if err != nil {
		panic(err)
	}
	defer c.Close()
	//...
	c.Write("type", []byte("message"))
	//...
	msg,err := c.Read()
	if err != nil {
		panic(err)
	}
	//...
```

### 二、服务端

#### 用法一：

```
	l, err := net.Listen("tcp", "0.0.0.0:port")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	for {
		c, err := easySecurityLink.Accept(l)
		if err != nil {
			panic(err)
		}
		defer c.Close()
		//使用c ...
	}
```

#### 用法二：

```
	l, err := net.Listen("tcp", "0.0.0.0:port")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		defer c.Close()
		conn, err := easySecurityLink.Upgrade(c)
		if err != nil {
			return err
		}
		defer conn.Close()
		//使用conn ...
	}
```

具体用法可以参考`examples`。


