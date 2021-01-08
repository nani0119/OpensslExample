rsautl 为 RSA 工具。本指令能够使用 RSA 算法签名，验证身份， 加密/解密数据。
用法：
openssl rsautl [-in file] [-out file] [-inkey file] [-pubin] [-certin] [-sign] [-verify] [-encrypt]
[-decrypt] [-pkcs] [-ssl] [-raw] [-hexdump] [-engine e] [-passin arg]
选项：
-in filename
指定输入文件名，缺省为标准输入。
-out filename
指定输入文件名， 缺省为标准输出。
-inkey file
输入私钥文件名。
-pubin
表明我们输入的是一个公钥文件，默认输入为私钥文件。
-certin
表明我们输入的是一个证书文件。
-sign
给输入的数据签名。
-verify
对输入的数据进行签名。
-encrypt
用公钥对输入数据加密。
-decrypt
用私钥对输入数据解密。
-pkcs, -oaep, -ssl, -raw
指定填充方式，上述四个值分别代表： PKCS#1.5(默认值)、 PKCS#1OAEP、
SSLv2 以及不填充。
-hexdump
用十六进制输出数据。
-engine e
指定硬件引擎。
-passin arg
指定私钥保护口令的来源，比如： -passin file:pwd.txt。
举例：
生成 RSA 密钥：
openssl genrsa -des3 -out prikey.pem
分离出公钥：
openssl rsa -in prikey.pem -pubout -out pubkey.pem
对文件签名：
openssl rsautl -sign -inkey prikey.pem -in a.txt -hexdump，文件 a.txt 的内容不能太长；
openssl rsautl -sign -inkey prikey.pem -in a.txt -out sig.dat
验证签名：
openssl rsautl -verify -inkey prikey.pem -in sig.dat，验证成功后打印出 a.txt 的内容；
公钥加密：
openssl rsautl -encrypt -pubin -inkey pubkey.pem -in a.txt -out b.txt
私钥解密：
openssl rsautl -decrypt -inkey prikey.pem -in b.txt
用证书中的公钥加密：
openssl rsautl -encrypt -certin -inkey cert1.pem -in a.txt
