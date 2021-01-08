dsaparam 命令用于生成和操作 dsa 参数。
用法：
openssl dsaparam [-inform DER|PEM] [-outform DER|PEM] [-in filename ] [-out
filename] [-noout] [-text] [-C] [-rand file(s)] [-genkey] [-engine id] [numbits]
选项：
-inform DER|PEM
输入文件格式。
-outform DER|PME
输出文件格式。
-in filename
输入文件名。
-out filename
输出文件名。
-nout
不打印输出信息。
-text
打印内容信息。
-C
以 C 语言格式打印信息。
-rand file(s)
指定随机数种子文件，多个文件用冒号分开。
-genkey
生成 dsa 密钥。
-engine id
指定硬件引擎。
number
生成密钥时指定密钥大小。
示例：
生成 DSA 密钥：
openssl dsaparam -genkey 512 -out dsa.pem
打印密钥信息：
openssl dsaparam -in dsa.pem -text
openssl dsaparam -in dsa.pem -C