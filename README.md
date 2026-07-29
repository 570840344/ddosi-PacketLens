<div align="center">
  
<h1>PacketLens 🔰雨苁ℒ🔰</h1>
<h3>浏览器内极速 pcap 深度分析工作台</h3>

<p>纯前端 · 零后端 · 离线可用 · HTTPS 解密 · 百万级数据包秒开</p>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![JavaScript](https://img.shields.io/badge/JavaScript-Vanilla-yellow.svg)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/your-repo/pull/new)

<strong>🌐 官方网站 / 在线体验 :</strong>
<p>
  <a href="https://www.ddosi.org/packetlens" target="_blank" rel="noopener noreferrer">
    <strong>www.ddosi.org/packetlens</strong>
  </a>
</p>
</div>

---
[简体中文](README.md) | [English](README_EN.md)

### 📖 项目简介
![图片](https://www.ddosi.org/wp-content/uploads/2026/07/205404.webp)
**PacketLens** 是一款专为网络安全分析与应急响应设计的纯前端 pcap 分析工具。它将传统桌面端流量分析工具（如 Wireshark）的核心能力搬到了浏览器中。

无需安装任何环境，无需后端服务器，只需双击打开 HTML 文件或将 pcap 文件拖入网页，即可完成从底层协议解码到上层威胁研判的全流程分析。**所有数据均在本地浏览器内处理，绝不上传，保障数据绝对安全。**

### ✨ 核心功能

- 🔍 **逐字节协议树解码**：支持 Ethernet/IPv4/IPv6/TCP/UDP/HTTP/TLS/DNS 等上百种协议，Wireshark 式字段树与十六进制双向联动高亮。
- 🔓 **HTTPS 深度解密**：支持导入 `SSLKEYLOGFILE` 或读取 pcapng 内嵌密钥块 (DSB)。实现 TLS 1.2/1.3 (AES-GCM, ChaCha20-Poly1305) 解密，内置 HTTP/2 HPACK 引擎，还原明文请求与响应。
- 🕵️ **取证与凭据提取**：自动提取 HTTP/FTP/Telnet 等明文协议中的账号密码；深度解析 JSON 请求体；内置正则引擎动态提取手机号、身份证、JWT Token、云厂商 AccessKey 等高价值敏感信息。
- 🛡️ **威胁情报与研判**：内置 40+ 专家诊断规则（端口扫描、ARP欺骗、DNS隧道、信标回连等）。对 IP/域名/JA3/证书/文件进行离线威胁评分，支持导入本地 IoC 库与白名单。
- 🚀 **极限性能与内存优化**：
  - 采用 Web Worker 多线程解析，主线程零阻塞。
  - 独创的“即用即弃”内存管理策略，支持百万级数据包秒级加载。
  - DOM 虚拟滚动与 V8 引擎底层优化，内存占用降至理论极限。
- 📊 **可视化与报告导出**：
  - 交互式通信拓扑图（力导向布局）。
  - 态势研判作战台（攻击链阶段归类、资产风险收敛）。
  - 一键导出排版精美的 HTML/Markdown 分析报告。
- **特点**：包含 IP 信息库（`GeoLite2-Country.mmdb` 和 `dbip-asn-lite-*.mmdb` 两个文件），支持在界面中直接显示 IP 归属国和 ASN 运营商信息。


### 快速开始(本地部署)

- **使用方法**：由于浏览器安全策略限制，直接双击打开无法加载 `.mmdb` 文件，需进行本地部署。
1. 在 [Releases](https://github.com/ddosi/PacketLens/releases) 页面下载最新版本.
2. 安装 [Python](https://www.python.org/downloads/) 环境。
3. 使用下面任意一种方法访问

      A.方法一：使用 HTTP 访问（最简单）

     在解压目录下运行命令：
     ```bash
     python -m http.server 80
     ```
     浏览器访问：[http://localhost/](http://localhost/) 或者[http://127.0.0.1/](http://127.0.0.1/)

   B. 方法二：使用 HTTPS 访问（推荐，功能最完整）**
     在解压目录下运行附带的脚本：
     ```bash
     python https.py
     ```
     脚本会自动调用系统 openssl 生成证书并启动服务。浏览器访问：[https://localhost:8443/](https://localhost:8443/) （浏览器会提示不安全，选择继续访问即可）。


#### 🔑 如何解密 HTTPS 流量？
现代 TLS 使用 ECDHE 前向保密，光有抓包文件无法解密。你需要从客户端侧获取会话密钥：

1. **浏览器/curl**：在启动前设置环境变量 `SSLKEYLOGFILE=/path/to/keys.log`。
2. **Node.js**：启动时加上 `--tls-keylog=/path/to/keys.log` 参数。
3. **导入工具**：将 `keys.log` 文件直接拖入 PacketLens 页面，或点击右上角“TLS 密钥”按钮导入。工具会自动重新解密并走一遍完整的应用层分析管线。

### 🛠️ 技术架构与性能压榨

PacketLens 完全使用原生 Vanilla JavaScript 编写，无任何外部框架依赖。为了处理超大流量，我们在底层做了极其硬核的优化：

- **零内存分配协议树**：统计阶段不创建数组对象，直接拼接字符串，消除百万级 GC 停顿。
- **Worker 通信降维**：Worker 解析完毕后，彻底剥离包对象的深层属性，仅传递基础展示数据至主线程；主线程按需通过 `ArrayBuffer.subarray` 重建视图，传输开销从 GB 级降至 MB 级。
- **极速 IP 过滤**：底层解析时将 IPv4 预转为 32 位无符号整数，过滤时进行数学比较，规避了大量字符串正则匹配，性能提升 10 倍以上。

### ⚠️ 安全与免责声明

- **数据隐私**：本工具纯本地运行，不会向任何第三方服务器发送你的抓包数据。但请注意，提取出的凭据、解密的明文等敏感信息缓存在浏览器内存中，关闭页面即销毁。
- **合法使用**：本工具仅供网络安全学习、教学和合法的授权安全测试使用。请勿用于任何非法用途。使用者需自行承担因不当使用本工具而产生的一切法律责任。

### 🤝 贡献代码

欢迎提交 Issue 和 Pull Request！如果你有新的协议解析需求、发现了 Bug，或者对性能优化有更好的思路，请随时联系我。

### 📜 开源许可证

本项目基于 [MIT License](LICENSE) 开源。

---

<div align="center">
  <p>Powered by <a href="https://www.ddosi.org" target="_blank" rel="noopener noreferrer" style="text-decoration:none;color:inherit">www.ddosi.org</a> 🔰雨苁ℒ🔰</p>
</div>
