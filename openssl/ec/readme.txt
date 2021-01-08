椭圆曲线密钥处理工具。
用法：
openssl ec [-inform PEM|DER] [-outform PEM|DER] [-in filename] [-passin arg] [-out
filename] [-passout arg] [-des] [-des3] [-idea] [-text] [-noout] [-param_out] [-pubin] [-pubout]
[-conv_form arg] [-param_enc arg] [-engine id]
选项：
-inform PEM|DER
输入文件格式。
-outform PEM|DER
输出文件格式。
-in filename
输入文件名。
-passin arg
私钥保护口令来源。
-out filename
输出文件名。
-passout arg
输出文件保护口令来源。
-des， -des3， -idea
私钥保护算法。
-noout
不输出信息。
-param_out
输出参数。
-pubin
输入的是公钥。
-pubout
输出公钥。
-conv_form arg
指定信息存放方式，可以是 compressed、 uncompressed 或者 hybrid，默认为
compressed。
-param_enc arg
指定参数编码方法，可以是 named_curve 和 explicit，默认为 named_curve。
-engine id
指定硬件引擎
示例：
1) 生成 ec 私钥
openssl ecparam -genkey -name secp112r1 -out eckey.pem -text
2) 转换为 DER 编码
openssl ec -outform der -in eckey.pem -out eckey.der
3) 给私钥进行口令保护
openssl ec -in eckey.pem -des -out enceckey.pem
4) 将公钥写入文件
openssl ec -in eckey.pem -pubout -out ecpubkey.pem
5） 显示密钥信息
openssl ec -in eckey.pem –text
openssl ec -in ecpubkey.pem -pubin –text
6） 转换为 pkcs8 格式
openssl pkcs8 -topk8 -in eckey.pem -out eckeypk8.pem