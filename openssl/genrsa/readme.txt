生成 RSA 密钥
用法：
openssl genrsa [-out filename] [-passout arg] [-des] [-des3] [-idea] [-f4] [-3] [-rand file(s)]
[-engine id] [numbits]

-des
以 des cbc 模式加密密钥；
-des3
以 3des cbc 模式加密密钥；
-idea
以 idea cbc 模式加密密钥；
-aes128, -aes192, -aes256
cbc 模式加密密钥；
-out file
输出文件；
-f4
指定 E 为 0x1001；
-3
指定 E 为 3；
-engine e
指定 engine 来生成 RSA 密钥；

-rand file
指定随机数种子文件；
numbits
密钥长度，如果不指定默认为 512。

示例：
openssl genrsa -des3 -out prikey.pem -f4 1024
从私钥中生成公钥
openssl rsa -in  prikey.pem -out pub.pem -pubout