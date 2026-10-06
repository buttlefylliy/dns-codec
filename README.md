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
* `encode_resource_record(record)`：把资源记录映射（键序不限）编码为线上字节。A/AAAA 记录只含 `name`、`type`、`class`、`ttl`、`address`；CNAME 记录只含 `name`、`type`、`class`、`ttl`、`target`。名称以未压缩形式写入，`type` 只接受整数 1（A）、5（CNAME）或 28（AAAA），`class` 为 16 位、`ttl` 为 32 位无符号整数（布尔值不被接受）；type 为 1 时 `address` 为无前导零的四段点分十进制 IPv4 字符串，RDLENGTH 固定为 4；type 为 28 时 `address` 为合法 IPv6 文本（不含首尾空白、区域标识与前缀长度，允许十六进制大小写、前导零、`::` 压缩与末尾 IPv4 嵌入写法），RDLENGTH 固定为 16，RDATA 为 128 位网络字节序，同一地址的不同合法写法产生相同字节；type 为 5 时 `target` 与 `name` 适用相同的绝对 ASCII 域名规则（根名 `.` 同样合法），以未压缩形式写入，RDLENGTH 等于目标名的实际线上长度。任何形状、类型、范围或取值非法（含 type 与 RDATA 形态不匹配、未知字段、`target` 非法）抛出 `DNSArgumentError`，校验完成前不返回结果且不修改输入。
* `decode_resource_record(message, offset=0)`：从完整消息的指定偏移读取一条记录，返回 `(record, next_offset)`；A/AAAA 的 `record` 为固定键序 `name`、`type`、`class`、`ttl`、`address`，CNAME 为固定键序 `name`、`type`、`class`、`ttl`、`target`。A 地址为规范点分十进制，AAAA 地址为规范 IPv6 文本（小写十六进制、各段无前导零、只压缩长度至少为两段的最长连续零段、并列取最左，IPv4 嵌入地址同样输出十六进制形式）；CNAME 的 RDATA 被解释为一个完整域名，接受与 `decode_name` 相同的合法向后压缩指针并保留标签大小写，RDLENGTH 区域必须恰好容纳该目标名。`next_offset` 始终指向该记录声明的 RDATA 末尾，不随压缩指针跳转目标改变。参数、超过 65535 字节的消息或越界偏移抛出 `DNSArgumentError`，名称畸形、固定字段或 RDATA 截断、CNAME 的 RDLENGTH 为零或不能恰好容纳一个目标名、名称或压缩指针畸形、A 的 RDLENGTH 不为 4、AAAA 的 RDLENGTH 不为 16、其他类型抛出 `DNSMessageError`，失败时不返回部分结果。
* 异常：`DNSArgumentError`、`DNSMessageError`。
* 头部计数不会被问题编解码读取或修改。

### 命令行

* `encode-header` / `decode-header`：头部编解码。
* `encode-question`：从标准输入读取 UTF-8 JSON 对象，输出仅含 `wire` 的紧凑 JSON。
* `decode-question`：读取十六进制字节，输出键序固定为 `name`、`qtype`、`qclass` 的紧凑 JSON；必须恰好消费一个完整问题，尾随字节或截断均按 message 错误处理（退出码 3）。
* `encode-record`：从标准输入读取 UTF-8 JSON 对象，输出仅含 `wire` 的紧凑 JSON。
* `decode-record`：读取十六进制字节，A/AAAA 输出键序固定为 `name`、`type`、`class`、`ttl`、`address` 的紧凑 JSON，CNAME 输出键序固定为 `name`、`type`、`class`、`ttl`、`target` 的紧凑 JSON；必须恰好消费一条完整记录，尾随字节或截断均按 message 错误处理（退出码 3）。
* 输入规模受 4096 字节上限约束；argument 错误退出码 2，message 错误退出码 3，错误以固定 JSON 结构写入标准错误。

## 状态

仓库初始为空，功能按增量需求持续构建。
