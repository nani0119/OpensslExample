使用下面命令生成, key的密码统一为111111
1.服务器
    1)生成服务器端的私钥
        openssl genrsa -des3 -out server.key 1024 
    2)生成CSR(Certificate Signing Request)
        openssl req -new -key server.key -out server.csr
2.客户端
    1)生成客户端的私钥
        openssl genrsa -des3 -out client.key 1024 
    2)生成CSR(Certificate Signing Request)
        openssl req -new -key client.key -out client.csr
3. CA
    1)生成CA的key文件
        openssl genrsa -des3 -out ca.key 1024
    2)生成CA自签名的证书
        openssl req -new -x509  -days 365000 -key ca.key -out ca.crt
    3)生成服务器端证书
        openssl x509 -req -days 365000 -CA ca.crt -CAkey ca.key -CAcreateserial -in server.csr -out server.crt -extensions IP=127.0.0.1
    4)生成客户端证书
        openssl x509 -req -days 365000 -CA ca.crt -CAkey ca.key -CAcreateserial -in client.csr -out client.crt 