# 项目待办

以下事项来自 2026-10-04 项目审查，按优先级排列。P1 为构建阻断，P2 为正确性、安全或测试问题。写入时同步了远端 `main`，已解决项注明修复提交。

- [x] **P1：补齐无捕获支持平台的 `Capture` 接口**
  - 状态：提交 `927858b` 已补齐占位 `read()`；macOS 主机验证尚未执行。
  - 位置：`src/capture.rs`，占位 `Capture` 实现及 `capture_web_events()`。
  - 问题：占位实现只有 `open()`，公共代码仍调用 `read()`，导致 macOS 和 Windows `--no-default-features` 无法编译；Windows 交叉检查已复现 `E0599`。
  - 验收：macOS 和 Windows 无默认特性构建通过；`web` 在不支持捕获时返回清晰错误，其他命令正常使用。

- [x] **P1：修复 Windows Npcap 后端编译错误**
  - 状态：提交 `927858b` 已删除无效导入并修正可变引用。
  - 位置：`src/capture.rs`，Windows 后端 `read()`、`attach_filter()` 和 `open()`。
  - 问题：`pcap 2.4.0` 不导出 `ActivatedCapture`；`filter()` 需要可变引用，当前 `attach_filter(&self)` 无法调用。Windows 全特性交叉检查已复现 `E0432` 和 `E0596`。
  - 验收：删除无效导入，修正可变引用及调用处；Windows 默认特性构建和 Clippy 通过。

- [ ] **P2：验证 IPv4 报文长度并跳过非首分片**
  - 位置：`src/proto.rs`，`parse_ipv4_for_web_events()`。
  - 问题：未检查分片偏移，也未限制到 IP 声明的总长度。独立探针确认非首分片及总长度之外的数据均可能被误识别为 DNS 查询。
  - 验收：传输层解析仅使用有效 IP 载荷；非首分片不产生域名事件；补充声明长度异常、尾随数据和分片偏移的回归测试。

- [ ] **P2：修正 IPv6 首分片判断**
  - 位置：`src/proto.rs`，`is_first_fragment()`。
  - 问题：当前要求偏移及标志字段整体为零，误将偏移为零、`M=1` 的首分片丢弃；独立探针已复现。
  - 验收：通过掩码单独判断分片偏移；测试覆盖 `M=1` 首分片、原子分片和非首分片。

- [ ] **P2：转义域名输出中的控制字符**
  - 位置：`src/proto.rs`，DNS/SNI 字符串解析；`src/capture.rs`，`print_web_events()`。
  - 问题：报文中的换行、ESC 等控制字符未经转义即可进入终端输出，可干扰显示或伪造输出行；独立探针确认 DNS 名称中的 ESC 被保留。
  - 验收：DNS 和 SNI 输出均安全处理控制字符，正常域名仍可读；补充换行和 ANSI 转义序列的回归测试。

- [x] **P2：修复 Windows 上的 netstat 样例测试**
  - 状态：提交 `927858b` 已按行结构选择列索引，并增加 Windows 样例测试。
  - 位置：`src/live.rs`，`parses_macos_netstat_line()` 和 `parses_linux_netstat_line()`。
  - 问题：测试未限制平台，但解析器在 Windows 上采用另一套列索引，将样例中的队列字段当作远端地址，导致断言失败。
  - 验收：按平台限制样例测试，或显式传入输出格式；增加 Windows 样例覆盖；三平台测试通过。

## 审查验证基线

以下为同步远端修复前的审查结果：

- Linux 全特性和无默认特性测试各 88 项通过。
- Linux `cargo fmt --all -- --check` 及全特性 Clippy 通过。
- Windows GNU 目标全特性及无默认特性交叉编译检查均失败，原因见上述 P1 项。
- 尚未在 macOS 或 Windows 主机上运行测试。

同步远端 `927858b` 和 `72f241a` 后的验证：

- Linux 全特性测试 90 项通过，包含新增 Windows netstat 样例。
- Windows GNU 目标全特性及无默认特性交叉编译检查均通过。
- macOS 和 Windows 主机上的运行验证仍以平台 CI 为准，本次未执行。
