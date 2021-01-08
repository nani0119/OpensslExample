生成随机数
openssl rand [-out file] [-rand file(s)] [-base64] num
选项：
-out file
结果输出到 file 中。
-engine e
采用 engine 来生成随机数。
-rand file
指定随机数种子文件。
-base64
输出结果为 BASE64 编码数据。
num
随机数长度。