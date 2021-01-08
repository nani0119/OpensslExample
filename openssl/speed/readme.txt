speed 命令用于测试库的性能。
用法：
openssl speed [-engine id] [md2] [mdc2] [md5] [hmac] [sha1] [rmd160]
[idea-cbc] [rc2-cbc] [rc5-cbc] [bf-cbc] [des-cbc] [des-ede3] [rc4]
[rsa512] [rsa1024] [rsa2048] [rsa4096] [dsa512] [dsa1024] [dsa2048]
[idea] [rc2] [des] [rsa] [blowfish]
选项：
-engine id
设置硬件引擎 id。
-elapsed
测量采用实时时间，不是所用 CPU 时间，两者时间差异较大。
-mr
生成机器可读显示。
-multi n
并行允许 n 个测试。

示例：
openssl speed md5