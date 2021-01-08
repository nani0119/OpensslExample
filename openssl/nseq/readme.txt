本命令用于多个证书与 netscape 证书序列间相互转化。
用法： openssl nseq [-in filename] [-out filename] [-toseq]
选项：
-in filename
输入文件名。
-out filename
输出文件名。
-toseq
含此项时将多个证书转化为 netscape 证书序列， 否则将 netscape 证书序列转化为多
个证书。
示例：
1) 将多个证书写成一个文件
cat newcert.pem > 1.pem
cat cacert.pem >> 1.pem
2) 将多个证书转化为 netscape 证书序列
openssl nseq -in 1.pem -toseq -out 2.pem
3) 将 netscape 证书序列转化为多个证书
openssl nseq -in 2.pem -out 3.pem