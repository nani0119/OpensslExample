在线证书状态工具。
用法：
openssl ocsp [-out file] [-issuer file] [-cert file] [-serial num] [-signer file] [-signkey file ]
[-sign_other file ] [-no_certs] [-req_text] [-resp_text] [-text] [-reqout file] [-respout file] [-reqin
file] [-respin file] [-nonce] [-no_nonce] [-url URL] [-host host:n] [-path] [-CApath dir] [-CAfile
file] [-VAfile file] [-validity_period n] [-status_age n] [-noverify] [-verify_other file] [-trust_other]
[-no_intern] [-no_signature_verify] [-no_cert_verify] [-no_chain] [-no_cert_checks] [-port num]
[-index file] [-CA file] [-rsigner file] [-rkey file] [-rother file] [-resp_no_certs] [-nmin n] [-ndays n]
[-resp_key_id] [-nrequest n]
选项：
-out file
指定输出文件，默认为标准输出。
-issuer file
指定当前颁发者证书，此选项可以用多次， file 中的证书必须是 PEM 格式的。
-cert file
将 file 指定的证书添加到 OCSP 请求中去。
-serial num
将数字证书序列号添加到 OCSP 请求中去， num 为证书序列号， 0x 开始表示
是十六进制数据，否则是十进制数据， num 可以是负数，前面用-表示。
-signer file, -signkey file
OCSP 请求签名时，分别指定证书和私钥；如果只设置-signer 选项，私钥和证
书都从-signer 指定的文件中读取；如果不设置这两项， OCSP 请求将不会被签名。
-sign_other filename
签名的请求中添加其他证书。
-no_certs
签名的请求中不添加任何证书。
-req_text
打印 OCSP 请求信息。
-resp_text
打印 OCSP 响应信息。
-text
打印 OCSP 请求或者响应信息。
-reqout file
指定 DER 编码的 OCSP 请求输出文件。
-respout file
指定 DER 编码的 OCSP 响应输出文件。
-reqin file
指定输入的 DER 编码的 OCSP 请求文件。
-respin file
指定输入的 DER 编码的 OCSP 响应文件。
-nonce， -no_nonce
设置或不设置 OCSP 中的 nonce 扩展。
-url URL
指定 OCSP 服务的 URL。
-host host:n
发送 OCSP 请求给服务， host 为地址或域名 n 为端口号。
-path
OCSP 请求所用的路径。
-CApath dir
可信 CA 文件目录， CA 文件名请参考其他章节说明。
-CAfile file
可信 CA 文件， file 可以包含多个 CA 证书。
-VAfile file
指定受信任的 OCSP 服务的证书， file 可以包含多个证书；等价于-verify_certs
和-trust_other 选项。
-validity_period n
设置 OCSP 响应中可接受的时间误差， n 以秒为单位。默认可接受时间误差为
5 秒， OCSP 认证中有关时间的说明请参考 OCSP 一章。
-status_age n
如果 OCSP 响应中没用提供响应的失效时间， 则说明马上可以获取到新的响应
信息；此时需要检查起始时间是否比当前时间晚 n 秒；默认情况不做此操作。
-noverify
不验证 OCSP 响应的签名和 nonce。
-verify_other file
设置其他用于搜索 OCSP 响应者证书的文件。
-trust_other
由-verify_other 指定的文件中包含了响应者的证书，用此选项时，不对响应者
证书做额外的验证。当不能获取响应者证书的证书链或其根 CA 时，可用此选项，
以保证验证能通过，即：使用了此选项后， verify_other 所指定的 OCSP 服务者证
书是可以信任的，即使那些证书有问题。
-no_intern
不搜索 OCSP 响应者的证书，采用此选项时， OCSP 响应者的证书必须在
-verify_certs 或-VAfile 中指定。
-no_signature_verify
不验证响应者的签名，用于测试。
-no_cert_verify
不验证响应者的证书，用于测试。
-no_chain
不验证响应者证书链。
-no_cert_checks
不验证响应者证书，不检查响应者是否有权来发布 OCSP 响应，用于测试。
-port num
OCSP 服务端口。
-index file
指定证书状态索引文件。
-CA file
指定 CA 证书。
-rsigner file
指定用于签发 OCSP 响应的证书。
-rkey file
指定用于签发 OCSP 响应的私钥文件。
-rother file
将其他证书添加到 OCSP 响应中。
-resp_no_certs
OCSP 响应中不包含证书。
-nmin n
距离下次更新时间， n 以分钟为单位
-ndays n
距离下次更新时间， n 以天为单位。
-resp_key_id
用响应者的私钥 ID 来标记 OCSP 响应，默认为响应者证书的持有者。
-nrequest n
OCSP 服务最大响应个数，默认无限制。
举例：
1）请先用 req 和 ca 命令生成 OCSP 服务证书和私钥，下面的 OCSP 服务证书为
ocspservercert.pem， OCSP 服务签名私钥为 ocspserverkey.pem
2）生成 OCSP 请求：
openssl ocsp -issuer demoCA/cacert.pem -cert cert.pem -cert -cert2.pem -reqout ocspreq.der
3）打印 OCSP 请求信息：
openssl ocsp -reqin ocspreq.der -text
4）启动 OCSP 服务：
openssl ocsp -ndays 1 -index demoCA/index.txt -port 3904 -CA demoCA/cacert.pem -text
-rkey ocspserverkey.pem -rsigner ocspservercert.pem
5）请求 OCSP 响应：
openssl ocsp -issuer demoCA/cacert.pem -url http://127.0.0.1:3904 -reqin ocspreq.der
-VAfile ocspservercert.pem -respout resp.der
打印如下信息：
Response verify OK
或者： openssl ocsp -issuer demoCA/cacert.pem -url http://127.0.0.1:3904 -cert cert.pem -cert
cert2.pem -VAfile ocspservercert.pem -respout resp.der
打印如下信息：
Response verify OK
cert.pem: unknown
This Update: Mar 9 16:50:12 2007 GMT
Next Update: Mar 10 16:50:12 2007 GMT
cert2.pem: revoked
This Update: Mar 9 16:50:12 2007 GMT
Next Update: Mar 10 16:50:12 2007 GMT
Revocation Time: Mar 9 13:56:51 2007 GMT
5） 根据响应的文件来验证：
openssl ocsp -respin resp.der -VAfile ocspserverc ert.pem -text