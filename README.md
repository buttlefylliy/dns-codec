# dns-codec

DNS 问题报文与资源记录的编解码、压缩指针与 DNAME 语义。

## 约束

* 仅使用 Python 标准库，不联网，不依赖第三方包。
* 行为必须确定：相同输入多次运行产生逐字节一致的输出；时间相关行为由显式注入的时钟驱动，不读墙上时钟。
* 所有结论可由公开接口与落盘产物独立验收。

## 公开入口

* 入口文件：`dns_codec.py` 
* 命令行：`python dns_codec.py --help` 
* 使用说明与行为契约以本文件为准；入口的签名、键序与既有语义在迭代中保持兼容。

### Python API

* `encode_header(header)` / `decode_header(data)`：12 字节 DNS 头部编解码。
* `encode_name(name)` / `decode_name(message, offset=0)`：绝对域名编解码，解码支持受限的向后压缩指针。
* `encode_question(question)`：把只含 `name`、`qtype`、`qclass` 的映射编码为未压缩名称加两个网络字节序 16 位值；缺字段、未知字段、类型错误或数值越界抛出 `DNSArgumentError`，校验完成前不返回结果且不修改输入。
* `decode_question(message, offset=0)`：从完整 DNS 消息的指定偏移读取一个问题，返回 `({"name", "qtype", "qclass"}, next_offset)`，键序固定；参数或偏移非法抛出 `DNSArgumentError`，名称畸形或末尾不足四字节抛出 `DNSMessageError`。
* `encode_resource_record(record)`：把只含 `name`、`type`、`class`、`ttl`、`address` 的映射（A、AAAA）、只含 `name`、`type`、`class`、`ttl`、`target` 的映射（CNAME、NS）、只含 `name`、`type`、`class`、`ttl`、`mname`、`rname`、`serial`、`refresh`、`retry`、`expire`、`minimum` 的映射（SOA，键序均不限）或只含 `name`、`type`、`class`、`ttl`、`strings` 的映射（TXT，键序均不限）编码为一条资源记录；名称以未压缩形式写入，`type` 只接受整数 1（A）、2（NS）、5（CNAME）、6（SOA）、16（TXT）或 28（AAAA），`class` 为 16 位、`ttl` 为 32 位无符号整数（布尔值不被接受）；type 为 1 时 `address` 为无前导零的四段点分十进制 IPv4 字符串，RDLENGTH 固定为 4；type 为 28 时 `address` 为合法 IPv6 文本（不含首尾空白、区域标识与前缀长度，允许十六进制大小写、前导零、`::` 压缩与末尾 IPv4 嵌入写法），RDLENGTH 固定为 16，RDATA 为 128 位网络字节序，同一地址的不同合法写法产生相同字节；type 为 2 或 5 时 `target` 遵循与 `name` 相同的绝对 ASCII 域名规则（含根名 `.`），RDATA 为未压缩的目标名，RDLENGTH 等于其实际长度；type 为 6 时 `mname`、`rname` 遵循与 `name` 相同的绝对 ASCII 域名规则（含根名 `.`），RDATA 依次为未压缩的 mname、未压缩的 rname 与 `serial`、`refresh`、`retry`、`expire`、`minimum` 五个网络字节序 32 位无符号整数（不接受布尔值），RDLENGTH 等于实际总长度，同一输入产生相同字节；type 为 16 时 `strings` 为非空 list 或 tuple，元素为偶数位十六进制字符串（字母大小写均可，空字符串表示零长度片段），各表示零至 255 字节的原始数据，RDATA 按顺序为每段写入单字节长度与原始字节，RDLENGTH 为全部长度字节与内容字节之和（不超过 65535 字节）；任何形状、类型、范围或取值非法（含 type 与字段不匹配，type 为 6 时出现 `address`、`target`、`strings` 或未知键，type 为 16 时出现 `address`、`target` 或未知键）抛出 `DNSArgumentError`，校验完成前不返回结果且不修改输入。
* `decode_resource_record(message, offset=0)`：从完整消息的指定偏移读取一条 A、AAAA、CNAME、NS、SOA 或 TXT 记录，返回 `({"name", "type", "class", "ttl", "address"}, next_offset)`（A、AAAA）、`({"name", "type", "class", "ttl", "target"}, next_offset)`（CNAME、NS）、`({"name", "type", "class", "ttl", "mname", "rname", "serial", "refresh", "retry", "expire", "minimum"}, next_offset)`（SOA）或 `({"name", "type", "class", "ttl", "strings"}, next_offset)`（TXT），键序固定，`next_offset` 始终指向所声明 RDATA 的末尾；A 地址为规范点分十进制，AAAA 地址为规范 IPv6 文本（小写十六进制、各段无前导零、只压缩长度至少为两段的最长连续零段、并列取最左，IPv4 嵌入地址同样输出十六进制形式）；CNAME 与 NS 的 RDATA 按一个完整域名解码（接受与 `decode_name` 相同的合法向后压缩指针，保留标签大小写），声明区域必须恰好容纳该名称；SOA 的 RDATA 严格限制在声明的 RDLENGTH 内依次解码 mname、rname 与恰好五个网络字节序 32 位无符号整数，两个名称均接受与 `decode_name` 相同的合法向后压缩指针并保留标签大小写，其原始编码不得越过声明区域；TXT 的 RDATA 严格限制在声明的 RDLENGTH 内逐段读取（不解释名称压缩），保持片段顺序，`strings` 中每段以小写十六进制表示（零长度片段为空字符串）；参数、超过 65535 字节的消息或越界偏移抛出 `DNSArgumentError`，名称或压缩指针畸形、名称原始编码越过声明区域、固定字段或 RDATA 截断、A 的 RDLENGTH 不为 4、AAAA 的 RDLENGTH 不为 16、CNAME、NS、SOA 或 TXT 的 RDLENGTH 为零、CNAME 或 NS 区域不能恰好容纳一个目标名、SOA 区域不能恰好容纳 mname、rname 与五个 32 位整数（整数不足或五个整数后仍有声明内剩余字节）、TXT 声明区域不能恰好分解为完整片段、其他类型抛出 `DNSMessageError`，失败时不返回部分结果。
* `encode_message(message)`：把只含 `header`、`questions`、`answers`、`authorities`、`additionals` 的映射编码为完整 DNS 报文；`header` 沿用 `encode_header` 规则，后四项为问题或资源记录映射的序列，`qdcount`、`ancount`、`nscount`、`arcount` 必须分别等于各段实际条目数；编码前完成全部校验且不修改输入，成功时按头部、问题段、回答段、权威段、附加段依次连接，名称保持未压缩编码，总长不超过 65535 字节；任何形状、类型、计数或长度非法抛出 `DNSArgumentError`。
* `decode_message(data)`：从同一份字节先解码头部，再严格按四个计数依次读取问题段与三个资源记录段（仅限 A、AAAA、CNAME、NS、SOA、TXT，各段可混合已有记录、SOA 与 TXT），名称允许 `decode_name` 接受的合法向后压缩指针；返回键序固定为 `header`、`questions`、`answers`、`authorities`、`additionals` 的映射，各条目键序沿用现有解码结果；非 bytes 或超过 65535 字节抛出 `DNSArgumentError`，计数要求的条目被截断、名称或记录畸形、记录类型不受支持、各段完成后仍有尾随字节均抛出 `DNSMessageError`，失败时不返回部分结果。
* 异常：`DNSArgumentError`、`DNSMessageError`。
* 头部计数不会被问题编解码读取或修改。

### 命令行

* `encode-header` / `decode-header`：头部编解码。
* `encode-question`：从标准输入读取 UTF-8 JSON 对象，输出仅含 `wire` 的紧凑 JSON。
* `decode-question`：读取十六进制字节，输出键序固定为 `name`、`qtype`、`qclass` 的紧凑 JSON；必须恰好消费一个完整问题，尾随字节或截断均按 message 错误处理（退出码 3）。
* `encode-record`：从标准输入读取 UTF-8 JSON 对象，输出仅含 `wire` 的紧凑 JSON。
* `decode-record`：读取十六进制字节，输出键序固定为 `name`、`type`、`class`、`ttl`、`address`（A、AAAA）、`name`、`type`、`class`、`ttl`、`target`（CNAME、NS）、`name`、`type`、`class`、`ttl`、`mname`、`rname`、`serial`、`refresh`、`retry`、`expire`、`minimum`（SOA）或 `name`、`type`、`class`、`ttl`、`strings`（TXT）的紧凑 JSON；必须恰好消费一条完整记录，尾随字节或截断均按 message 错误处理（退出码 3）。
* `encode-message`：从标准输入读取 UTF-8 JSON 对象（仅含 `header`、`questions`、`answers`、`authorities`、`additionals`），输出仅含 `wire` 的紧凑 JSON。
* `decode-message`：读取十六进制完整报文，输出键序固定为 `header`、`questions`、`answers`、`authorities`、`additionals` 的紧凑 JSON；截断、畸形、不支持的记录类型或尾随字节均按 message 错误处理（退出码 3）。
* 输入规模受 4096 字节上限约束；argument 错误退出码 2，message 错误退出码 3，错误以固定 JSON 结构写入标准错误。

## 状态

仓库初始为空，功能按增量需求持续构建。
