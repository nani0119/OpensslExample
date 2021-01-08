显示支持的加密套件
用法：
openssl ciphers [-v] [-ssl2] [-ssl3] [-tls1] [cipherlist]
选项：
-v
详细列出所有加密套件。包括 ssl 版本、密钥交换算法、身份验证算法、
对称算法、摘要算法以及该算法是否可以出口。
-ssl3
只列出 SSLv3 使用的加密套件。
-ssl2
只列出 SSLv2 使用的加密套件。
-tls1
只列出 TLSv1 使用的加密套件。
cipherlist
此项为一个规则字符串，用此项能列出所有符合规则的加密套件，如果不
加-v 选项，它只显示各个套件名字；
示例：
openssl ciphers -v 'ALL:eNULL'
openssl ciphers -v '3DES:+RSA