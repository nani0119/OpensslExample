证书验证工具、
用法：
openssl verify [-CApath directory] [-CAfile file] [-purpose purpose] [-untrusted file] [-
help] [-issuer_checks] [-verbose] [-crl_check] [-engine e] [certificates]
选项
-CApath directory
信任的 CA 证书存放目录，它们的文件名为 xxxx.0，其中 xxxx 为其证书持有
者的摘要值，通过 openssl x509 -hash -in cacert1.pem 可以获取。
-CAfile file
CA 证书，当其格式为 PEM 格式时，里面可以有多个 CA 证书。
-untrusted file
不信任的 CA 的证书，一个文件中可有多个不信任 CA 证书。
-purpose purpose
证书的用途，如果不设置此选项，则不会验证证书链。 purpose 的值可以是： s
slclient、 sslserver、 nssslserver、 smimesign 和 smimeencrypt。
-help
打印帮助信息。
-verbose
打印详细信息。
-issuer_checks
打印被验证书与 CA 证书间的关系。
-crl_check
验证 CRL，可以将 CRL 内容写在 CAfile 指定的 PEM 文件中。
certificates
待验证的证书。
举例：
上一节，我们制作了两个证书： cert1.pem 和 cert2.pem，并撤销了 cert2.pem，生成了一
个 crl 文件。在此基础上，我们将 crl 文件的内容拷贝到 demoCA/cacert.pem 的结尾，然后做
如下验证命令：
openssl verify -CAfile demoCA/cacert.pem -verbose -purpose sslclient -crl_check cer
t1.pem cert2.pem
会有如下信息：
Electric Fence 2.2.0 Copyright (C) 1987-1999 Bruce Perens <bruce@perens.com>
cert1.pem: OK
cert2.pem: /C=CN/ST=JS/O=WX/OU=JN/CN=test2/emailAddress=test22@a.net
error 23 at 0 depth lookup:certificate revoked
出错信息用户请参考 verify 文档。