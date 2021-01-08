version： 打印版本以及 openssl 其他各种信息
errstr:   用于查询错误代码
rand：    生成随机数
prime:    检查一个数是否为素数
passwd：  生成各种口令密文
asn1parse:用来诊断 ASN.1 结构的工具，也能用于从 ASN1.1 数据中提取数据
speed：   用于测试库的性能




dgst:      数据摘要,签名，验签




enc:      对称加解密工具，还可以进行 base64 编码转换




dhparam:  dh参数操作和生成工具

genrsa：  生成 RSA 密钥
rsa:      用于处理 RSA 密钥、格式转换和打印信息
rsatul:   RSA 工具,能够使用 RSA 算法签名，验证身份， 加密/解密数据

ecparam:  椭圆曲线密钥参数生成及操作
ec:       椭圆曲线密钥处理工具

dsaparam:用于生成和操作 dsa 参数
gendsa:DSA 密钥参数生成 DSA 密钥
dsa:用于处理 DSA 密钥、格式转换和打印信息




req：用于生成和处理 PKCS#10 证书请求(x509 请求)
crl:用于处里 PME 或 DER 格式的 CRL 文件
ca:一个小型 CA 系统。它能签发证书请求和生成 CRL。它维护一个已签发证书状态的文本数据库。
x509：多用途的证书工具。它可以显示证书信息、转换证书格式、签名证书请求以及改变证书的信任设置
verify:证书验证工具
nseq:用于多个证书与 netscape 证书序列间相互转化
ocsp:在线证书状态工具




crl2pkcs7:根据 CRL 或证书来生成 pkcs#7 消息
pkcs7:用于处理 DER 或者 PEM 格式的 pkcs#7 文件
pkcs8:私钥转换工具
pkcs12:能生成和分析 pkcs12 文件




ciphers:显示支持的加密套件
sess_id：SSL/TLS 协议的 session 处理工具
s_server：openssl 提供的一个 SSL 服务程序
s_client：SL/TLS 客户端程序，与 s_server 对应，它不仅能与 s_server 进行通信，也能与任何使用 ssl 协议的其他服务程序进行通信
s_time:SL/TLS 性能测试工具，用于测试 SSL/TSL 服务。




smime:用于处理 S/MIME 邮件，它能加密、解密、签名和验证 S/MIME 消息