dsa 命令用于处理 DSA 密钥、格式转换和打印信息。
用法：
openssl dsa [-inform PEM|DER] [-outform PEM|DER] [-in filename]
[-passin arg] [-out filename] [-passout arg] [-des] [-des3] [-idea]
[-text] [-noout] [-modulus] [-engine id]
选项：
-inform
输入 dsa 密钥格式， PEM 或 DER。
-outform
输出文件格式， PEM 或 DER。
-in filename
输入的 DSA 密钥文件名。
-passin arg
指定私钥包含口令存放方式。比如用户将私钥的保护口令写入一个文件，采用
此选项指定此文件，可以免去用户输入口令的操作。比如用户将口令写入文件
“ pwd.txt”，输入的参数为： -passin file:pwd.txt。
-out filename
指定输出文件名。
-passout arg
输出文件口令保护存放方式。
-des -des3 -idea
指定私钥保护加密算法。
-text
打印所有信息。
-noout
不打印信息。
-modulus
打印公钥信息。
-engine id
指定引擎。
示例：
1) 生成 dsa 参数文件
openssl dsaparam -out dsaparam.pem 1024
2) 根据 dsa 参数文件生成 dsa 密钥
openssl gendsa -out dsakey.pem dsaparam.pem
3) 将 PME 密钥转换为 DER 密钥
openssl dsa -in dsakey.pem -outform DER -out dsakeyder.pem
4) 打印公钥信息
openssl dsa -in dsakey.pem –modulus
5) 打印所有信息
openssl dsa -in dsakey.pem –text
6) 将 dsa 密钥加密存放
openssl dsa -in dsakey.pem -des -out enckey.pem