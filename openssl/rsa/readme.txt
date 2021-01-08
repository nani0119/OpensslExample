Rsa 命令用于处理 RSA 密钥、格式转换和打印信息。
用法：
openssl rsa [-inform PEM|NET|DER] [-outform PEM|NET|DER] [-in filename] [-passin
arg] [-out filename] [-passout arg] [-sgckey] [-des] [-des3] [-idea] [-text] [-noout] [-modulus]
[-check] [-pubin] [-pubout] [-engine id]
选项：
-inform DER|PEM|NET
指定输入的格式， NET 格式是与老的 Netscape 服务以及微软的 IIS 兼容的一
种不太安全的格式。
-outform DER|PEM|NET
指定输出格式。
-in filename
输入文件名。
-passin arg
私钥保护密钥来源，比如： -passin file:pwd.txt
out filename
输出的文件名。
-des|-des3|-idea
指定私钥保护加密算法。
-text
打印密钥信息。
-noout
不打印任何信息。
-modulus
打印密钥模数。
-pubin
表明输入文件为公钥，默认的输入文件是私钥。
-pubout
表明输出文件为公钥。
-check
检查 RSA 私钥。
-engine id
指明硬件引擎。
示例：
生成明文私钥文件：
openssl genrsa -out key.pem
转换为 DER 编码：
openssl rsa -in key.pem -outform der -out key.der
将明文私钥文件转换为密码保护：
openssl rsa -inform der -in key.der -des3 -out enckey.pem
将公钥写入文件：
openssl rsa -in key.pem -pubout -out pubkey.pem
打印公钥信息：
openssl rsa -pubin -in pubkey.pem –text -modulus
显示私钥信息，保护密钥写在 pwd.txt 中
openssl rsa -in enckey.pem –passin file:pwd.txt
