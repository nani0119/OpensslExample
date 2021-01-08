s_time 是 openss 提供的 SSL/TLS 性能测试工具，用于测试 SSL/TSL 服务。
用法：
openssl s_time [-connect host:port] [-www page] [-cert filename] [-key filename]
[-CApath directory] [-CAfile filename] [-reuse] [-new] [-verify depth] [-nbio] [-time seconds]
[-ssl2] [-ssl3] [-bugs] [-cipher cipherlist]
用法：
-connect host:port
指定服务，默认为本机的 4433 端口。
-www page
指定获取的 web 网页。
-cert filename
指定证书。
-key filename
指定私钥。
-CApath directory
指定 CA 文件目录。
-CAfile filename
指定 CA 文件。
-reuse
session 重用。
-new
新建链接。
-verify depth
设置验证深度。
-nbio
不采用 BIO。
-time seconds
指定搜集数据的秒数，默认 30 秒。
-ssl2， -ssl3
采用的 SSL 协议。
-bugs
开启 SSL bug 兼容。
-cipher cipherlist
指定加密套件。
示例：
1） 启动 s_server 服务：
openssl s_server -cert sslservercert.pem -key sslserverkey.pem -ssl3
2) 启动 s_time
openssl s_time -cert sslclientcert.pem -key sslclientkey.pem -CAfile
demoCA/cacert.pem -ssl3