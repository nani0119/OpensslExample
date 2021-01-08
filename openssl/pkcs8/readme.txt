pkcs8 格式的私钥转换工具。
用法：
openssl pkcs8 [-inform PEM|DER] [-outform PEM|DER] [-in filename] [-passin arg]
[-out filename] [-passout arg] [-topk8] [-noiter] [-nocrypt] [-nooct] [-embed] [-nsdb] [-v2 alg]
[-v1 alg] [-engine id]
选项：
-inform PEM|DER
输入文件格式。
-outform PEM|DER
输出文件格式。
-in filename
输入文件。
-passin arg
输入文件口令保护来源。
-out filename
指定输出文件。
-passout arg
输出文件口令保护来源。
-topk8
输出 pkcs8 文件。
-noiter
MAC 保护计算次数为 1。
-nocrypt
加密输入文件，输出的文件不被加密。
-nooct
不采用八位组表示私钥。
-embed
采用嵌入式 DSA 参数格式。
-nsdb
采用 Netscape DB 的 DSA 格式。
-v2 alg
采用 PKCS#5 v2.0，并指定加密算法，可以是 des、 des3 和 rc2，推荐 des3。
-v1 alg
采用 PKCS#5 v1.5 或 pkcs12，并指定加密算法，可采用算法包括：
PBE-MD2-DES 、 PBE-MD5-DES 、 PBE-SHA1-RC2-64 、 PBE-MD2-RC2-64 、
PBE-MD5-RC2-64、 PBE-SHA1-DES、 PBE-SHA1-RC4-128、 PBE-SHA1-RC4-40、
PBE-SHA1-3DES、 PBE-SHA1-2DES、 PBE-SHA1-RC2-128 和 PBE-SHA1-RC2-40。
-engine i
指定硬件引擎。
示例：
1） 将私钥文件转换为 pkcs8 文件：
openssl pkcs8 -in ocspserverkey.pem -topk8 -out ocspkcs8key.pem
2） pkcs8 中的私钥以明文存放：
openssl pkcs8 -in ocspserverkey.pem -topk8 -nocrypt -out ocspkcs8key.pem