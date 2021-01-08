本命令根据 CRL 或证书来生成 pkcs#7 消息。它只能将 crl 转换为 pkcs7 格式的信息。
用法：
openssl crl2pkcs7 [-inform PEM|DER ] [-outform PEM|DER ] [-in filename ] [-out
filename ] [-certfile filename ] [-nocrl ]
选项：
-inform PME|DER
CRL 输入格式，默认为 PEM 格式。
-outform PME|DER
pkcs#7 输出格式，默认为 PEM 格式。
-in filename
指定 CRL 文件，不设置此项则从标准输入中获取。
-out filename
指定输出文件，不设置此项则输入到标准输出。
-certfile filename
指定证书文件， PEM 格式的证书文件可以包含多个证书，此选项可以多次使用。
-nocrl
不处理 crl。一般情况下，输出文件中包含 crl 信息，设置此选项时，读取时忽
略 CRL 信息，生成的信息不保护 CRL 信息。
示例：
openssl crl2pkcs7 -in crl.crl -out crlpkcs7.pem
openssl crl2pkcs7 -in crl.crl -certfile demoCA/ca cert.pem -out crlcertpkcs7.pem
openssl crl2pkcs7 -in crl.crl -certfile demoCA/ca cert.pem -out certpkcs7.pem –nocrl
上面生成的三个 pkcs7 文件包含的内容是不同的， crlpkcs7.pem 只有 crl 信息；
crlcertpkcs7.pem 既有 crl 信息又有证书信息； certpkcs7.pem 只有证书信息。
所以，不要被 crl2pkcs7 名字所迷惑，以为它只能将 crl 转换为 pkcs7 格式的信息。
