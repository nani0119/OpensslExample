S/MIME 工具，用于处理 S/MIME 邮件，它能加密、解密、签名和验证 S/MIME 消息。
用法：
openssl smime [-encrypt] [-decrypt] [-sign] [-verify] [-pk7out] [-des]
[-des3] [-rc2-40] [-rc2-64] [-rc2-128] [-in file] [-certfile file]
[-signer file] [-recip file] [-inform SMIME|PEM|DER] [-passin arg]
[-inkey file] [-out file] [-outform SMIME|PEM|DER] [-content file] [-to
addr] [-from ad] [-subject s] [-text] [-rand file(s)] [cert.pem]...
主要选项：
-encrypt
加密数据。
-decrypt
解密数据。
-sign
签名数据。
-verify
验证数据。
-in
输入文件名。
-out
输出文件名。
-pk7out
输出 pkcs7 格式的文件。
-des -des3 -rc2-40 –rc2-60 –rc2-128
对称算法。
-signer file
指定签名者证书。
-recip file
指定接收者证书。
-inform
输入文件格式。
-passin arg
私钥保护口令来源。
-inkey file
私钥文件。
-outform
输出文件格式。
示例：
1) 用对方的证书来加密消息
openssl smime -encrypt -in mail.pem -out enced.pem newcert.pem
openssl smime -encrypt -in mail.pem -out enced.pem -des newcert.pem
2） 用私钥解密消息
openssl smime -decrypt -in enced.pem -out mymail.pem -inkey newkey.pem
openssl smime -decrypt -in enced.pem -out mymail.pem -inkey newkey.pem -des
3）用自己的私钥签名数据
openssl smime -sign -in mail.pem -out signedmail.pem -inkey newkey.pem -signer
newcert.pem
4) 验证签名
openssl smime -verify -in signedmail.pem -CAfile newcert.pem -signer newcert.pem
此处 newcert 是一个自签名证书，如果不是自签名证书用如下命令：
openssl smime -verify -in signedmail.pem -CAfile demoCA/cacert.pem -signer
newcert2.pem
5) 将数据转化为 pkcs7 格式
openssl smime -pk7out -in signedmail.pem -out p7.pem