openssl help dgst 
options are
-c              to output the digest with separating colons        //输出的摘要信息以分号隔离，和-hex同时使用
-r              to output the digest in coreutils format           //指定输出的格式
-d              to output debug info                               //输出BIO调试信息
-hex            output as hex dump                                 //以16进制打印输出结果
-binary         output in binary form                              //输出二进制结果
-hmac arg       set the HMAC key to arg                            //指定hmac的key
-non-fips-allow allow use of non FIPS digest                       //允许使用不符合fips标准的摘要算法
-sign   file    sign digest using private key in file              //执行签名操作，后面指定私钥文件
-verify file    verify a signature using public key in file        //执行验证操作，后面指定公钥文件，与prverfify不能同时使用
-prverify file  verify a signature using private key in file       //执行验证操作，后面指定密钥文件，与verfify不能同时使用
-keyform arg    key file format (PEM or ENGINE)                    //指定密钥文件格式，pem或者engine

-out filename   output to filename rather than stdout              //指定输出文件，默认标准输出
-signature file signature to verify                                //指定签名文件，在验证签名时使用
-sigopt nm:v    signature parameter                                //签名参数
-hmac key       create hashed MAC with key                         //制作一个hmac 使用key
-mac algorithm  create MAC (not neccessarily HMAC)                 //制作一个mac
-macopt nm:v    MAC algorithm parameters or key                    //mac算法参数或者key
-engine e       use engine e, possibly a hardware device.          //使用硬件或者三方加密库
-md4            to use the md4 message digest algorithm            //摘要算法使用md4
-md5            to use the md5 message digest algorithm            //摘要算法使用md5
-ripemd160      to use the ripemd160 message digest algorithm      //摘要算法使用ripemd160
-sha            to use the sha message digest algorithm            //摘要算法使用sha
-sha1           to use the sha1 message digest algorithm           //摘要算法使用sha1
-sha224         to use the sha224 message digest algorithm         //摘要算法使用sha223
-sha256         to use the sha256 message digest algorithm         //摘要算法使用sha256
-sha384         to use the sha384 message digest algorithm         //摘要算法使用sha384
-sha512         to use the sha512 message digest algorithm         //摘要算法使用sha512
-whirlpool      to use the whirlpool message digest algorithm      //摘要算法使用whirlpool]


示例:
摘要：
对file.txt文件使用sha1算法进行hash运算
openssl dgst -sha1 file.txt

RSA签名：
从密钥中提取公钥
openssl rsa -in RSA.pem -out pub.pem -pubout

摘要算法选取sha256，密钥RSA密钥，对file.txt进行签名
openssl dgst -sign RSA.pem -sha256 -out rsasign.txt file.txt

使用RSA私钥验证签名(prverify参数)，验证成功
openssl dgst -prverify RSA.pem -sha256 -signature rsasign.txt file.txt

使用RSA公钥验证签名(verify参数)，验证成功
openssl dgst -verify pub.pem -sha256 -signature rsasign.txt file.txt 