req 命令主要用于生成和处理 PKCS#10 证书请求
p10证书一般是一个base64文件，实际上他不是一张真正的证书应该是一段可以向CA申请证书的P10请求，
该请求一般是通过硬件生成密钥对后，将私钥单独存放，但是将公钥放入p10中，CA受到该p10请求后，
可以校验，并根据p10中的信息制作一张没有私钥的公钥证书。

用法：
openssl req [-inform PEM|DER] [-outform PEM|DER] [-in filename] [-passin arg] [-out
filename] [-passout arg] [-text] [-pubkey] [-noout] [-verify] [-modulus] [-new] [-rand file(s)]
[-newkey rsa:bits] [-newkey dsa:file] [-nodes] [-key filename] [-keyform PEM|DER] [-keyout
filename] [-[md5|sha1|md2|mdc2]] [-config filename] [-subj arg] [-multivalue-rdn] [-x509] [-days
n] [-set_serial n] [-asn1-kludge] [-newhdr] [-extensions section] [-reqexts section] [-utf8]
[-nameopt] [-batch] [-verbose] [-engine id]

选项：
-out
指定输出文件名。
-outform DER|PEM
指定输出格式。
-newkey rsa:bits
用于生成新的 rsa 密钥以及证书请求。如果用户不知道生成的私钥文件名称，
默认采用 privkey.pem，生成的证书请求。如果用户不指定输出文件(-out)，则将证
书请求文件打印在屏幕上。生成的私钥文件可以用-keyout 来指定。生成过程中需
要用户输入私钥的保护口令以及证书申请中的一些信息
-new
生成新的证书请求以及私钥，默认为 1024 比特。
-rand
指定随机数种子文件，比如有随机数文件 rand.dat，用户输入： -rand file:rand.dat。
-config file
指定证书请求模板文件，默认采用 openssl.cnf，需另行指定时用此选项。配置
的写法可以参考 openssl.cnf，其中有关于生成证书请求的设置。
-subj arg
用于指定生成的证书请求的用户信息，或者处理证书请求时用指定参数替换。
生成证书请求时，如果不指定此选项，程序会提示用户来输入各个用户信息，包括
国名、组织等信息，如果采用此选择，则不需要用户输入了。比如： -subj
/CN=china/OU=test/O=abc/CN=forxy，注意这里等属性必须大写。
-multivalue-rdn
当 采 用 -subj arg 选 项 时 ， 允 许 多 值 rdn 名 ， 比 如 arg 参 数 写 作 ：
/CN=china/OU=test/O=abc/UID=123456+CN=forxy。
-reqexts ..
设置证书请求的扩展项，被设置的扩展项覆盖配置文件所指定的扩展项。
-utf8
输入字符为 utf8 编码，默认输入为 ASCII 编码。
-batch
不询问用户任何信息（私钥口令除外），采用此选项生成证书请求时，不询问
证书请求当各种信息。
-noout
不输出证书请求。
-newhdr
在生成的 PME 证书请求文件的头尾添加“ NEW”，有些软件和 CA 需要此项。
-engine e
指定硬件引擎。
-keyout
指定生成的私钥文件名称

示例：
openssl req –new
openssl req –new –config myconfig.cnf
openssl req –subj /CN=cn/O=test/OU=abc/CN=forxy
openssl req -newkey rsa:1024
openssl req -newkey rsa:1024 -out myreq.pem –keyout myprivatekey.pem
openssl req -newkey rsa:1024 -out myreq.pem -keyout myprivatekey.pem -outform DER
-subject
输出证书请求者信息。
-modulus
输出证书请求的模数。
示例： openssl req -in myreq.pem -modulus –subject。
-pubkey
获取证书请求中的公钥信息。
示例：
openssl req -in myreq.pem -pubkey -out pubkey.pem
-in filename
输入的证书请求文件。
-text
打印证书请求或自签名证书信息。
-verify
验证证书请求。
示例：
openssl req -in zcp.pem -verify
-inform DER|PEM
指定输入的格式是 DEM 还是 DER。
-x509
生成自签名证书。
-extensions ..
设置证书扩展项，设置的扩展项优先于配置文件指定的扩展项。
-set_serial
设置生成证书的证书序列号，比如 -set_serial 100 或 -set_serial 0x100
-[md5|md4|md2|sha1|mdc2]
生成自签名证书时，指定摘要算法。
-passin
用户将私钥的保护口令写入一个文件，采用此选项指定此文件，可以免去用户
输入口令的操作。比如用户将口令写入文件“ pwd.txt”，输入的参数为： -passin
file:pwd.txt。
-days
指定自签名证书的有效期限。
示例：
openssl req -in myreq.pem -x509 -key myprivatekey.pem -out mycert.pem
openssl req -in myreq.pem -x509 -key myprivatekey.pem -out mycert.pem -days 300
openssl req -in myreq.pem -x509 -key myprivatekey.pem -out mycert.pem -days 300 -text
openssl req -in myreq.pem -x509 -key myprivatekey.pem -out mycert.pem -days 300 -text -md5
openssl req -in myreq.pem -x509 -key myprivatekey.pem -out mycert.pem -days 300 -text -md5 –set_serial 0x100
openssl req -in myreq.pem -x509 -key myprivatekey.pem -out mycert.pem -days 300 -text -md5 –passin file:pwd.txt
这里的 myreq.pem 为 PEM 格式的文件，可以用-inform 指定其格式。

-out filename
要输出的文件名。
-text
将 CSR 文件里的内容以可读方式打印出来。
-noout
不要打印 CSR 文件的编码版本信息。
-modulus
将 CSR 里面的包含的公共米要的系数打印出来。
-verify
检验请求文件里的签名信息。
示例：
生成 ECC 证书请求：
openssl ecparam -genkey -name secp160r1 -out ec160.pem
openssl req -newkey ec:ec160.pem
注意，如果由 ecparam 中的 -name 指定的密钥长度太短，将不能生成请求。因为 md5
或者 sha1 等的摘要长度对它来说太长了。