X509 命令是一个多用途的证书工具。它可以显示证书信息、转换证书格式、签名证书 请求以及改变证书的信任设置等。

用法：
openssl x509 [-inform DER|PEM|NET] [-outform DER|PEM|NET] [-keyform DER|PEM]
[-CAform DER|PEM] [-CAkeyform DER|PEM] [-in filename] [-out filename] [-serial] [-hash]
[-subject_hash] [-issuer_hash] [-subject] [-issuer] [-nameopt option] [-email] [-startdate] [-enddate]
[-purpose] [-dates] [-modulus] [-fingerprint] [-alias] [-noout] [-trustout] [-clrtrust] [-clrreject]
[-addtrust arg] [-addreject arg] [-setalias arg] [-days arg] [-set_serial n] [-signkey filename]
[-x509toreq] [-req] [-CA filename] [-CAkey filename] [-CAcreateserial] [-CAserial filename]
[-text] [-C] [-md2|-md5|-sha1|-mdc2] [-clrext] [-extfile filename] [-extensions section] [-engine id]

选项：
-inform DER|PEM|NET
指定输入文件的格式，默认为 PEM 格式。
-outform DER|PEM|NET
指定输出文件格式，默认为 PEM 格式。
-keyform
指定私钥文件格式，默认为 PEM 格式。
-CAform
指定 CA 文件格式，默认为 PEM 格式。
-CAkeyform
指定 CA 私钥文件格式，默认为 PEM 格式。
-in filename
指定输入文件名
-out filename
指定输出文件名。
-passin
指定私钥保护密钥来源，参考 req 说明，比如： -passin file:pwd.txt。
-serial
显示证书的序列号。
-subject_hash
显示持有者的摘要值。
-issuer_hash
显示颁发者的摘要值。
-hash
显示证书持有者的摘要值，同-subject_hash
-subject
显示证书持有者 DN。
-issuer
显示证书颁发者 DN。
-email
显示 email 地址。
-enddate
显示证书到期时间。
-startdate
显示证书的起始有效时间。
-purpose
显示证书用途。
-dates
显示证书的有效期。
-modulus
显示公钥模数。
-pubkey
输出公钥。
-fingerprint
打印证书微缩图。
-alias
显示证书别名。
-noout
不显示信息。
-ocspid
显示持有者和公钥的 OCSP 摘要值。
-trustout
输出可信任证书。
-clrtrust
清除证书附加项里所有有关用途允许的内容。
-clrreject
清除证书附加项里所有有关用途禁止的内容。
-addtrust arg
添加证书附加项里所有有关用途允许的内容。
-addreject arg
添加证书附加项里所有有关用途禁止的内容。
-setalias arg
设置证书别名。
-days arg
设置证书有效期。
-checkend arg
显示证书在给定的 arg 秒后是否还有效。
-signkey filename
指定自签名私钥文件。
-x509toreq
根据证书来生成证书请求，需要指定签名私钥，如：
openssl x509 -in ca.pem -x509toreq -signkey key.pem
-req
输入为证书请求，需要进行处理。
-CA arg
设置 CA 文件，必须为 PEM 格式。
-CAkey arg
设置 CA 私钥文件，必须为 PEM 格式。
-CAcreateserial
如果序证书列号文件，则生成。
-CAserial arg
由 arg 指定序列号文件。
-set_serial
设置证书序列号。
-text
打印证书信息。
-C
用 C 语言格式显示信息。
-md2|-md5|-sha1|-mdc2
指定使用的摘要算法，缺省为 MD5。
-extfile filename
指定包含证书扩展项的文件名，如果没有，那么生成的证书将没有任何扩展项。
-clrext
删除证书所有的扩展项。当一个证书由另外一个证书生成时，可用此项。
-nameopt option
指定打印名字时采用的格式。
-engine e
采用硬件引擎 e。
-certopt arg
当采用-text 显示时，设置是否打印哪些内容， arg 可用是： compatible、 no_header、
no_version、 no_extensions 和 ext_parse 等等， 详细信息请参考 x509 命令的帮助文档。
示例：
openssl x509 -in cert.pem -noout -subject -nameopt RFC2253
openssl x509 -in cert.pem -inform PEM -out cert.der -outform DER
openssl x509 -req -in req.pem -extfile openssl.cnf -extensions v3_usr -CA cacert.pem -CAkey key.pem –Cacreateserial