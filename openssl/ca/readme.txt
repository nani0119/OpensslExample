ca 命令是一个小型 CA 系统。它能签发证书请求和生成 CRL。它维护一个已签发证书
状态的文本数据库。
用法：
openssl ca [-verbose] [-config filename] [-name section] [-gencrl]
[-revoke file] [-crl_reason reason] [-crl_hold instruction] [-crl_com
promise time] [-crl_CA_compromise time] [-subj arg] [-crldays days]
[-crlhours hours] [-crlexts section] [-startdate date] [-enddate date]
[-days arg] [-md arg] [-policy arg] [-keyfile arg] [-key arg] [-passin
arg] [-cert file] [-in file] [-out file] [-notext] [-outdir dir]
[-infiles] [-spkac file] [-ss_cert file] [-preserveDN] [-noemailDN]
[-batch] [-msie_hack] [-extensions section] [-extfile section] [-engine
id] B[-utf8] [-multivalue-rdn]


选项：
-verbose
打印附加信息。
-config
指定配置文件，此配置文件中包含了证书存放路径、私钥和生成证书控制等信
息。如果默认安装 openssl，配置文件在/usr/local/ssl/路径下。我们可以先用 apps
目录下的 CA.sh 或者 CA.pl 脚本来 建立环境： sh CA.sh -newca,输入后回车就会
生成一个 demonCA 的目录。
-name section
替换配置文件指定的 default_ca 所表示的内容。比如有 openssl.cnf 配置如下：
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = ./demoCA
certs = $dir/certs
crl_dir = $dir/crl
database = $dir/index.txt
[ my_defaultCA ]
dir = ./demoCA1
certs = $dir/certs
crl_dir = $dir/crl
database = $dir/index.txt
此时用户也可以采用选项来指定 default_ca 的值： -name my_defaultCA;
-gencrl
生成 CRL 文件。
-revoke file
撤销证书， file 文件中包含了证书。
-crl_reason reason
设 置 CRLv2 撤 销 原 因 ， 原 因 可 以 为 ： unspecified 、 keyCompromise 、
CACompromise、 affiliationChanged、 superseded、 cessationOfOperation、 certificateHold
和 removeFromCRL。这些原因区分大小写。
-crl_hold instruction
当 crl 撤销原因为 certificateHold 时(证书挂起)，采用此项来指定用户行为。
instruction 的 值 可 以 是 ： holdInstructionNone 、 holdInstructionCallIssuer 和
holdInstructionReject。比如用选项： -crl_hold holdInstructionReject 时， 指明用户必
须拒绝挂起的证书。

-crl_compromise time
当 crl 撤销原因为 keyCompromise 时(密钥泄露),设置密钥泄露时间 time。 Time
采用通用时间格式： YYYYMMDDHHMMSSZ。
-crl_CA_compromise time
当 crl 撤销原因为 CACompromise 时(CA 被破坏),设置其时间，格式同
-crl_compromise time。
-subj arg
持有者参数，如/CN=cn/O=test/OU=t/cn=forxy，忽略空格已经\后的字符。
-crldays days
设置下次 CRL 发布时间， days 为下次发布时间距现在的天数。
-crlhours hours
设置下次 CRL 发布时间， hours 为下次发布时间距现在的小时数。
-crlexts section
指定 CRL 扩展项。 section 为配置文件中的段，如果不提供 crl 扩展项段，则
生成第一版本的 crl，如果提供，则生成第二版本的 crl。
-startdate date
设置证书生效起始时间，采用 UTCTime 格式： YYMMDDHHMMSSZ。
-enddate date
设置证书失效时间，采用 UTCTime 格式： YYMMDDHHMMSSZ。
-days arg
设置证书有效期， arg 为天数。
-md arg
设置摘要算法： md5、 sha、 sha1 或 mdc2。
-policy arg
指定 CA 策略， arg 为配置文件中的策略段，比如配置文件有如下信息：
[ ca ]
policy = policy_match
[ policy_match ]
countryName = match
stateOrProvinceName = match
organizationName = match
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
[ policy_anything ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
此时，采用的是 policy_match 策略(由 policy=policy_match 指定)，用户可以设
置采用 policy_anything： -policy policy_anything。
-keyfile arg
指定签发证书的私钥文件。
-key arg
指定私钥解密口令。
-passin arg
指定私钥口令来源。
-cert file
指定 CA 文件。
-in file
输入的证书请求文件。
-out file
输出文件名。
-notext
在证书文件中，不输出文本格式的证书信息。
-outdir dir
设置输出路径。
-infiles ...
处理多个证书请求文件，此选项必须放在最后，此选项后的多个输入都被当作
是证书请求文件
-ss_cert file
指定需要由 CA 签发的自签名证书。
-preserveDN
证书中的 DN 顺序由配置文件来决定，如果设置此选项，则证书中 DN 的顺序
与请求文件一致。
-noemailDN
如果证书请求者 DN 中包含邮件项，生成的证书也将会在持有者 DN 中包含。
但是，较好的方式是将它放入到扩展项(altName)中去，如果设置了此选项，则进
行这种操作。
-batch
批处理，不询问用户信息。
-msie_hack
支持很老的 IE 证书请求。
-extensions section
如果没有通过-extfile 选项指定扩展项信息， section 为配置文件中与扩展项有
关的段，签发证书时添加 section 指定的扩展项(默认采用 x509_extensions)，如果不
指定扩展，将生成第一版本的数字证书。
-engine id
指定硬件引擎。
-utf8
表明任何输入都必须是 utf8 编码(用户的终端输入和配置文件),默认为 ASCII 编码。
-multivalue-rdn
当 采 用 -subj 参 数 时 ， 支 持 多 值 RDN ， 比 如 ：
DC=org/DC=OpenSSL/DC=users/UID=123456+CN=John Doe。
示例：下面所有命令在 apps 目录下运行：
1） 建 CA
在 apps 目录下
sh ca.sh -newca 生成新 CA，遇到提示，直接回车；
2) 生成证书请求
openssl req -new -out req.pem -keyout key.pem
openssl req -new -out req2.pem -keyout key2.pem
3) 签发证书
openssl ca -config /usr/local/ssl/openssl.cnf -name CA_default -days 365 -md sha1
-policy policy_anything -cert demoCA/cacert.pem -in req.pem -out cert1.pem
-preserveDN -noemailDN -subj /CN=CN/O=JS/OU=WX/cn=myname -extensions myexts
openssl.cnf 中相关内容如下：
[ myexts ]
basicConstraints=CA:FALSE
sComment = "OpenSSL Generated Certificate test"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
openssl ca -cert demoCA/cacert.pem -in req2.pem -out cert2.pem
4) 撤销一个证书
openssl ca -revoke cert2.pem
5) 生成 crl，设置原因、挂起处理方法
openssl ca -gencrl -out crl.crl
openssl ca -gencrl -crl_reason keyCompromise -crl_compromise 20010101030303Z
-crl_hold holdInstructionReject -crl_CA_compromise 20020101030303Z
-crldays 10 -out crl2.crl
生成一个 crl 时需要一个 crlnumber，它是一个文本文件，内容为数字，比如： 03。