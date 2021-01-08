s_server 是 openssl 提供的一个 SSL 服务程序。使用此程序前，需要生成各种证书
本命令可以用来测试 ssl 客户端，比如各种浏
览器的 https 协议支持。
用法：
openssl s_server [-accept port] [-context id] [-verify depth] [-Verify
depth] [-cert filename] [-key keyfile] [-dcert filename] [-dkey keyfile] [-dhparam filename] [-nbio] [-nbio_test] [-crlf] [-debug] [-msg]
[-state] [-CApath directory] [-CAfile filename] [-nocert] [-cipher
cipherlist] [-quiet] [-no_tmp_rsa] [-ssl2] [-ssl3] [-tls1] [-no_ssl2]
[-no_ssl3] [-no_tls1] [-no_dhe] [-bugs] [-hack] [-www] [-WWW] [-HTTP]
[-engine id] [-rand file(s)]

选项：
-accept arg
监听的 TCP 端口，缺省为 443。
-context arg
设置 ssl 上下文，不设置时采用缺省值
-cert certname
服务使用的证书文件名。
-certform arg
证书文件格式，默认为 PEM。
-keyform arg
私钥文件格式，默认为 PEM。
-pass arg
私钥保护口令来源。
-msg
打印协议内容。
-timeout
设置超时。
-key keyfile
服务使用的私钥文件，由-cert 指定的文件既可以包含证书，也可用包含私钥，
此时，就不需要此选项。
-no_tmp_rsa
不生成临时 RSA 密钥。
-verify depth
设置证书验证深度。
-Verify arg
如果设置了此项为 1，服务端必须验证客户端身份。
-CApath path
设置信任 CA 文件所在路径，此路径中的 ca 文件名采用特殊的形式： xxx.0。
其中 xxx 为 CA 证书持有者的哈希值，可通过 x509 -hash 命令获得。
-CAfile file
指定 CA 证书文件。
-state
打印 SSL 握手状态。
-debug
打印更多的信息
-nbio
不采用 BIO。
-quiet
不打印输出信息。
-ssl2, -ssl3, -tls1
只采用某一种协。 ；
-no_ssl2, -no_ssl3, -no_tls1
不采用某种协议。
-www
返回给用户一个网页，内容为 SSL 握手的一些内容。
WWW -HTTP
将 某 个 文 件 作 为 网 页 发 回 客 户 端 ， 例 如 client 的 URL 请 求 是
https://myhost/page.html ，则把 ./page.html 发回给 client。如果不设置-www、
-WWW 、 -HTTP,客户端在终端输入任何字符，服务端都会响应同样的字符给客户端。
-rand file:file:...
设置随机数种子文件， SSL 协议握手中会生成随机数，比如 clienthello 和
serverhello 消息。
-crlf
将用户在终端输入的换行回车转化成/r/n。
连接命令，这些输入不是程序运行选项，在程序运行过程中输入，如下：
q
中断当前连接，但不关闭服务。
Q
中断当前连接，退出程序。
r
重新协商。
R
重新协商，并且要求客户端证书。
P
在 TCP 层直接送一些明文，造成客户端握手错误并断开连接。
S
打印缓存的 SESSION 信息。
