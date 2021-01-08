Dhparam 为 dh 参数操作和生成工具。 dh 命令与 dhparam 用法大致一致，下面只给出了
dhparam 的说明。
用法：
openssl dhparam [-inform DER|PEM] [-outform DER|PEM] [-in filename] [-out
filename] [-dsaparam] [-noout] [-check] [-text] [-C] [-2] [-5] [-rand file(s)] [-engine id]
[numbits]

选项：
-inform DER|PEM
输入文件格式， DER 或者 PEM 格式。
-outform DER|PEM
输出格式。
-in filename
读取 DH 参数的文件，默认为标准输入。
-out filename
dh 参数输出文件，默认为标准输出。
-dsaparam
生成 DSA 参数，并转换为 DH 格式。
-noout
不输出信息。
-text
打印信息。
-check
检查 dh 参数。
-C
以 C 语言风格打印信息。
-2， -5
指定 2 或 5 为发生器，默认为 2，如果指定这些项，输入 DH 参数文件将被忽
略，自动生成 DH 参数。
-rand files
指定随机数种子文件。
-engine id
指定硬件引擎。
numbit
指定素数 bit 数，默认为 512。
示例：
1) openssl dhparam –out dhparam.pem -text 512
生成内容如下：
Diffie-Hellman-Parameters: (512 bit)
prime:
00:8f:18:1b:4f:7a:74:e1:89:42:e6:99:0f:15:4e:
72:ad:ca:7b:fb:68:ef:85:7b:16:a8:5b:85:01:82:
dd:db:57:1f:c5:86:89:fa:16:10:6e:d0:05:2b:15:
e2:87:98:0e:53:f2:c8:18:f9:5b:7e:4d:ce:9b:6d:
3f:23:11:52:63
generator: 2 (0x2)
-----BEGIN DH PARAMETERS-----
MEYCQQCPGBtPenThiULmmQ8VTnKtynv7aO+FexaoW4UBgt3bVx/Fhon6FhBu0AUr
FeKHmA5T8sgY+Vt+Tc6bbT8jEVJjAgEC
-----END DH PARAMETERS-----
2) 检查生成的 DH 参数
openssl dhparam -in dhparam.pem -text -check