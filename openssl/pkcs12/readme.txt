pkcs12 文件工具，能生成和分析 pkcs12 文件。
用法：
openssl pkcs12 [-export] [-chain] [-inkey filename] [-certfile filename] [-CApath arg]
[-CAfile arg] [-name name] [-caname name] [-in filename] [-out filename] [-noout] [-nomacver]
[-nocerts] [-clcerts] [-cacerts] [-nokeys] [-info] [-des] [-des3] [-aes128] [-aes192] [-aes256] [-idea]
[-nodes] [-noiter] [-maciter] [-twopass] [-descert] [-certpbe alg] [-keypbe alg] [-keyex] [-keysig]
[-password arg] [-passin arg] [-passout arg] [-rand file(s)] [-engine e]
选项：
-export
输出 pkcs12 文件。
-chain
添加证书链。
-inkey filename
指定私钥文件，如果不用此选项，私钥必须在-in filename 中指定。
-certfile filename
添加 filename 中所有的文件。
-CApath arg
指定 CA 文件目录。
-CApath arg
指定 CA 文件。
-name name
指定证书和私钥的友好名。
-caname name
指定 CA 友好名，可以多次使用此选项。
-in filename
指定私钥和证书读取的文件，必须为 PEM 格式。
-out filename
指定输出的 pkcs12 文件，默认为标准输出。
-noout
不输出信息。
-nomacver
读取文件时不验证 MAC。
-nocerts
不输出证书。
-clcerts
只输出客户证书，不包含 CA 证书。
-cacerts
只输出 CA 证书，不包含 CA 证书。
-nokeys
不输出私钥。
-info
输出 pkcs12 结构信息。
-des3， -aes128 ， -aes192， [-aes256， [-idea
私钥加密算法； 。
-nodes
不对私钥加密。
-noiter
不多次加密。
-maciter
加强完整性保护，多次计算 MAC。
-twopass
需要用户分别指定 MAC 口令和加密口令。
-descert
用 3DES 加密 pkcs12 文件，默认为 RC2-40。
-certpbe alg
指定证书加密算法，默认为 RC2-40。
-keypbe alg
指定私钥加密算法，默认为 3DES。
-keyex
设置私钥只能用于密钥交换。
-keysig
设置私钥只能用于签名。
-password arg
指定导入导出口令来源。
-passin arg
输入文件保护口令来源。
-passout arg
指定所有输出私钥保护口令来源。
-rand file(s)
指定随机数种子文件，多个文件间用分隔符分开， windows 用“ ;”， OpenVMS
用“ ,“，其他系统用“： ”。
-engine e
指定硬件引擎。
举例：
1）生成 pkcs12 文件，但不包含 CA 证书：
openssl pkcs12 -export -inkey ocspserverkey.pem -in ocspservercert.pem -out
ocspserverpkcs12.pfx
2） 生成 pcs12 文件，包含 CA 证书：
openssl pkcs12 -export -inkey ocspserverkey.pem -in ocspservercert.pem -CAfile
demoCA/cacert.pem -chain -out ocsp1.pfx
3） 将 pcks12 中的信息分离出来，写入文件：
openssl pkcs12 –in ocsp1.pfx -out certandkey.pem
4） 显示 pkcs12 信息：
openssl pkcs12 –in ocsp1.pfx -info