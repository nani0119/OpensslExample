椭圆曲线密钥参数生成及操作。
用法：
openssl ecparam [-inform DER|PEM] [-outform DER|PEM] [-in filename] [-out
filename] [-noout] [-text] [-C] [-check] [-name arg] [-list_curve] [-conv_form arg]
[-param_enc arg] [-no_seed] [-rand file(s)] [-genkey] [-engine id]
用法：
-inform DER|PEM
输入文件格式。
-outform DER|PEM
输出文件格式。
-in filename
输入文件。
-out filename
输出文件。
-noout
不打印信息。
-text
打印信息。
-C
以 C 语言风格打印信息。
-check
检查参数。
-name arg
采用短名字。
-list_curves
打印所有可用的短名字。
-conv_form arg
指定信息存放方式，可以是 compressed、 uncompressed 或者 hybrid，默认为
compressed。
-param_enc arg
指定参数编码方法，可以是 named_curve 和 explicit，默认为 named_curve。
-no_seed
如果-param_enc 指定编码方式为 explicit，不采用随机数种子。
-rand file(s)
指定随机数种子。
-genkey
生成密钥。
-engine id
指定硬件引擎。
示例：
openssl ecparam -list_curves
openssl ecparam -name secp112r1 -genkey –text
openssl ecparam -genkey -name secp160r1 -out ec160.pem
openssl req -newkey ec:ec160.pem