crl 工具，用于处里 PME 或 DER 格式的 CRL 文件。
用法：
openssl crl [-inform PEM|DER] [-outform PEM|DER] [-text] [-in filename] [-out filename]
[-noout ] [-hash] [-issuer ] [-lastupdate ] [-nextupdate ] [-CAfile file ] [-CApath dir ]
选项：
-inform PEM|DER
输入文件格式，默认为 PEM 格式。
-outform PEM|DER
输出文件格式，默认为 PEM 格式。
-text
打印信息。
-in filename
指定输入文件名，默认为标准输入。
-out filename
指定输出文件名，默认为标准输出。
-noout
不打印 CRL 文件内容。
-hash
打印值。
-issuer
打印颁发者 DN。
-lastupdate
上次发布时间。
-nextupdate
下次发布时间。
-CAfile file
指定 CA 文件。
-CApath dir
指定多个 CA 文件路径，每个 CA 文件的文件名为 XXXX.0， XXXX 为其持有
者摘要值。
示例：
请先参考 CA 一节来生成一个 CRL 文件，再做如下操作：
openssl crl -in crl.crl -text -issuer -hash -lastupdate –nextupdate 显示 CRL 信息；
验证 CRL：
openssl crl -in crl.crl -CAfile demoCA/cacert.pem –noout
输出结果：
verify OK
下面通过指定 CA 文件路径来验证；
在 demoCA 目录下建立一个目录： CAfiles
openssl x509 -in demoCA/cacert.pem -hash 得到如下值： (比如)
86cc3989
在 CAfiles 下建立一个 86cc3989.0 文件，内容为 demoCA/cacert.pem 的内容
验证 CRL：
openssl crl -in crl.crl -CApath demoCA/CAfiles –noout