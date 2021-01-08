enc 为对称加解密工具，还可以进行 base64 编码转换。

用法：
openssl enc -ciphername [-in filename] [-out filename] [-pass arg] [-e ] [-d ] [-a ] [-A] [-k
password ] [-kfile filename] [-K key] [-iv IV] [-p] [-P] [-bufsize number] [-nopad] [-debug]
选项：
-ciphername
对称算法名字，此命令有两种适用方式： -ciphername 方式或者省略 enc 直接
用 ciphername。比如，用 des3 加密文件 a.txt：
openssl enc -des3 -e -in a.txt -out b.txt
openssl des3 -e -in a.txt -out b.txt

-in filename
输入文件，默认为标准输入。
-out filename
输出文件，默认为标准输出。
-pass arg
输入文件如果有密码保护，指定密码来源。
-e
进行加密操作，默认操作。
-d
进行解密操作。
-a
当进行加解密时，它只对数据进行运算，有时需要进行 base64 转换。设置此
选项后，加密结果进行 base64 编码；解密前先进行 base64 解码。
-A
默认情况下， base64 编码结果在文件中是多行的。如果要将生成的结果在文件
中只有一行，需设置此选项；解密时，必须采用同样的设置，否则读取数据时会出
错。
-k password
指定加密口令，不设置此项时，程序会提示用户输入口令。
-kfile filename
指定口令存放的文件。
-K key
输入口令是 16 进制的。
-iv IV
初始化向量，为 16 进制。
比如： openss des-cbc -in a.txt -out b.txt -a -A -K 1111 -iv 2222
-p
打印出使用的 salt、口令以及初始化向量 IV。
-P
打印使用的 salt、口令以及 IV，不做加密和解密操作。
-bufsize number
设置 I/O 操作的缓冲区大小，因为一个文件可能很大，每次读取的数据是
有限的。
-debug
打印调试信息。
进行 base64 编码时，将 base64 也看作一种对称算法