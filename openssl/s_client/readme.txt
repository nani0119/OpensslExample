s_client 为一个 SSL/TLS 客户端程序，与 s_server 对应，它不仅能与 s_server 进行
通信，也能与任何使用 ssl 协议的其他服务程序进行通信。

用法：
openssl s_client [-connect host:port>] [-verify depth] [-cert filename]
[-key filename] [-CApath directory] [-CAfile filename] [-reconnect]
[-pause] [-showcerts] [-debug] [-msg] [-nbio_test] [-state] [-nbio]
[-crlf] [-ign_eof] [-quiet] [-ssl2] [-ssl3] [-tls1] [-no_ssl2]
[-no_ssl3] [-no_tls1] [-bugs] [-cipher cipherlist] [-engine id] [-rand file(s)]
选项：
-host host
设置服务地址.
-port port
设置服务端口，默认为 4433。
-connect host:port
设置服务地址和端口。
-verify depth
设置证书验证深度。
-cert arg
设置握手采用的证书。
-certform arg
设置证书格式，默认为 PEM。
-key arg
指定客户端私钥文件名， 私钥可以与证书存放同一个文件中， 这样， 只需要-cert
选项就可以了，不需要本选项。
-keyform arg
私钥格式，默认为 PEM。
-pass arg
私钥保护口令来源，比如： -pass file:pwd.txt，将私钥保护口令存放在一个文件
中，通过此选项来指定，不需要用户来输入口令。
-CApath arg
设置信任 CA 文件所在路径，此路径中的 ca 文件名采用特殊的形式： xxx.0，
其中 xxx 为 CA 证书持有者的哈希值，它通过 x509 -hash 命令获得。
-CAfile arg
指定 CA 文件名。
-reconnect
重新连接，进行 session 重用。
-pause
每当读写数据时， sleep 1 秒。
-showcerts
显示证书链。
-debug
额外输出信息。
-msg
打印协议消息。
-nbio_test
更多协议测试。
-state
打印 SSL 状态。
-nbio
不采用 BIO。
-quiet
不显示客户端数据。
-ssl2、 -ssl3、 -tls1、 -dtls1
指定客户端协议。
-no_tls1/-no_ssl3/-no_ssl2
不采用某协议。
-bugs
兼容老版本服务端的中的 bug。
-cipher
指定加密套件。
-starttls protocol
protocol 可以为 smtp 或 pop3，用于邮件安全传输。
-rand file:file:...
设置随机数种子文件， SSL 协议握手中会生成随机数，比如 clienthello 和
serverhello 消息中的随机数。
-crlf
将用户在终端输入的换行回车转化成/r/n。