生成各种口令密文。
用法：
openssl passwd [-crypt] [-1] [-apr1] [-salt string] [-in file] [-stdin] [-noverify] [-quiet]
[-table] {password}
选项：
-crypt
默认选项，生成标准的 unix 口令密文。
-1
md5 口令密文。
-apr1
Apache md5 口令密文。
-salt string
加入由 string 指定的 salt。
-in file
输入的口令文件，默认从 stdin 中读取。
-stdin
默认选项，从 stdin 读取口令。
-noverify
用户输入口令时，不验证。
-quiet
无警告。
-table
用户输入的口令和结果用缩进隔开。
-reverse
用户输入的口令和结果用缩进隔开，输出内容颠倒顺序。
示例：
(1) openssl passwd
(2) openssl passwd -1
(3) openssl passwd -1 –noverify
(4) openssl passwd –table –reverse -noverify