sess_id 为 SSL/TLS 协议的 session 处理工具。
用法：
openssl sess_id [-inform PEM|DER] [-outform PEM|DER] [-in filename] [-out filename]
[-text] [-noout] [-context ID]

选项：
-inform DER|PEM
指定输入格式是 DER 还是 PEM；
-outform DER|PEM
指定输出格式是 DER 还是 PEM；
-in filename
session 信息的文件名；
-out filename
输出 session 信息的文件名；
-text
打印信息；
-cert
打印数字证书；
如果用户需要分析 session 信息，需要有一个 session 文件，用户可在程序中将
SSL_SESSION 写入文件，然后用本命令来分析。
