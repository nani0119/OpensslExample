pkcs7 命令用于处理 DER 或者 PEM 格式的 pkcs#7 文件。
用法：
openssl pkcs7 [-inform PEM|DER] [-outform PEM|DER] [-in filename] [-out filename]
[-print_certs] [-text] [-noout] [-engine id]
选项：
-inform DER|PEM
输入文件格式，默认为 PEM 格式。
-outform DER|PEM
输出文件格式，默认为 PEM 格式。
-in filename
输入文件名，默认为标准输入。
-out filename
输出文件名, 默认为标准输出。
-print_certs
打印证书或 CRL 信息，在一行中打印出持有者和颁发者。
-text
打印证书相信信息。
-noout
不打印信息。
-engine id
指定硬件引擎。
示例：
把一个 PKCS#7 文件从 PEM 格式转换成 DER 格式：
openssl pkcs7 -in file.pem -outform DER -out file.der
打印文件所有证书
openssl pkcs7 -in file.pem -print_certs -out certs.pem