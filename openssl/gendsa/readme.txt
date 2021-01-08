gendsa 根据 DSA 密钥参数生成 DSA 密钥， dsa 密钥参数可用 dsaparam 命令生成。
用法：
openssl gendsa [-out filename] [-des] [-des3] [-idea] [-rand file(s)] [-engine id] [paramfile]
选项：
-out filename
指定输出文件。
-des|-des3|-idea|-aes128|-aes192|-aes256
指定私钥口令保护算法，如果不指定，私钥将被明文存放。
-rand file(s)
指定随机数种子文件，多个文件用冒号分开。
-engine id
指定硬件引擎。
paramfile
指定使用的 DSA 密钥参数文件。
示例：
生成 DSA 参数：
openssl dsaparam -genkey 512 -out dsaparam.pem
生成 DSA 密钥：
openssl gendsa -des3 -out encdsa.pem dsaparam.pem