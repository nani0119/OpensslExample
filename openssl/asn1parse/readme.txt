openssl asn1parse [-inform PEM|DER] [-in filename] [-out filename] [-noout] [-offset
number] [-length number] [-i] [-oid filename] [-strparse offset] [-genstr string ] [-genconf file]


1. openssl asn1parse -i -in server.pem -inform pem
    ->8:d=2  hl=2 l=  20 prim:   INTEGER           :07F25AB87D0CA01323D59A2118549442799A29BC
        8:offset 2:deep　2:head length  20:内容长度　prime :类型

示例如下：
openssl asn1parse –in server.pem –out server.cer
此命令除了显示上面内容外，并生成一个 der 编码的文件。
openssl asn1parse –in server.pem –i
此命令显示上面的内容，但是有缩进。
openssl asn1parse -in server.pem -i -offset 455
此命令从偏移量 455 开始分析，到结束。注意， 455 从前面命令的结果得到。
openssl asn1parse -in server.pem -i -offset 455 -length 11
此命令从偏移量 455 进行分析，分析长度为 11
openssl asn1parse -in server.pem -i -dump
分析时，显示 BIT STRING 等的十六进制数据；
openssl asn1parse -in server.pem -i -dlimit 10
分析时，显示 BIT SRING 的前 10 个十六进制数据。
openssl asn1parse -in server.pem -i -strparse 453
此令分析一个偏移地址　该地址对应的是SEQUENCE
openssl asn1parse -in server.pem -i -strparse 453 -offset 2 -length 11
根据偏移量和长度分析。