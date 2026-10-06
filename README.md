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
* 异常：`DNSArgumentError`、`DNSMessageError`。
* 头部计数不会被问题编解码读取或修改。

### 命令行

* `encode-header` / `decode-header`：头部编解码。
* `encode-question`：从标准输入读取 UTF-8 JSON 对象，输出仅含 `wire` 的紧凑 JSON。
* `decode-question`：读取十六进制字节，输出键序固定为 `name`、`qtype`、`qclass` 的紧凑 JSON；必须恰好消费一个完整问题，尾随字节或截断均按 message 错误处理（退出码 3）。
* 输入规模受 4096 字节上限约束；argument 错误退出码 2，message 错误退出码 3，错误以固定 JSON 结构写入标准错误。

## 状态

仓库初始为空，功能按增量需求持续构建。
