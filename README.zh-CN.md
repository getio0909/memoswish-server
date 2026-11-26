[English](README.md)

# 忆刷服务端 Memoswish Server

[![CI](https://github.com/getio0909/memoswish-server/actions/workflows/server.yml/badge.svg)](https://github.com/getio0909/memoswish-server/actions/workflows/server.yml) [![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

官网与文档: <https://getio0909.github.io/memoswish-website/>

忆刷（Memoswish）是一款靠滑动卡片来做碎片化学习的应用，本仓库是它的 Rust 服务端。

项目还在 1.0 正式发布之前的开发阶段。服务端提供应用用到的 HTTP API，用 FSRS 生成复习信息流，也支持导入 Anki 卡组和忆刷 DeckPack。MCP 客户端可以通过 stdio 或 Streamable HTTP 管理学习内容。默认使用 SQLite 和本地资产存储；换一种部署方式，也可以用 PostgreSQL 和兼容 S3 的存储。

## 环境要求

需要带有 Cargo、rustfmt 和 Clippy 的稳定版 Rust。本次验证用的是 Rust 1.100.0。构建需要 C/C++ 工具链和 CMake，下面的命令还要用到 GNU Make 和 curl。

## 快速开始

在仓库根目录运行以下命令。

```sh
make run-server
```

服务端监听 `127.0.0.1:8787`，首次启动时会写入演示卡片。在另一个终端里检查服务是否已经起来。

```sh
curl --fail http://127.0.0.1:8787/v1/server-info
```

用[忆刷客户端](https://github.com/getio0909/memoswish-app)连接服务端。如果要从本地 MCP 客户端启动服务端，可以用 `make mcp-stdio`。

## 配置

参考[内嵌部署配置示例](server/config/memoswishd.example.toml)，用全局参数 `--config` 把配置文件传给 `memoswishd`。对于可以覆盖的选项，优先级从高到低依次是命令行参数、环境变量、TOML 文件和内置默认值。单用户模式不需要登录，本地开发时请保留默认监听地址。语音合成默认未配置。

[水平部署配置示例](server/config/memoswishd.horizontal.example.toml)需要外部的 PostgreSQL、Redis 和兼容 S3 的对象存储。如果选用外部认证、语音或邮件服务，需要分别配置。

## 构建与测试

在仓库根目录运行以下命令。

```sh
cargo build --locked --manifest-path server/Cargo.toml -p memoswishd
make server-check
```

默认的工作区测试使用 SQLite。标记为忽略的集成测试各有运行前提，例如 PostgreSQL、Redis、espeak-ng 或备份工具。

## 目录结构

- `server/` 包含 Cargo 工作区、配置示例和容器构建文件。
- `protocol/` 包含 JSON Schema 和协议测试数据。`compatibility/` 包含历史协议及数据库迁移测试数据。
- `brand/` 提供共享构建信息。`scripts/` 提供测试和备份工具。
- `deploy/` 包含单实例服务、反向代理和监控配置示例。

## 贡献与安全

请阅读[贡献指南](CONTRIBUTING.md)和[行为准则](CODE_OF_CONDUCT.md)。请按[安全政策](SECURITY.md)私下报告漏洞。

## 许可证

[Apache-2.0](LICENSE)。依赖项的授权声明见 [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt)。仓库中的品牌图稿同样采用该许可证。根据其第 6 条，该许可证不授予将 Memoswish 名称或标志用作商标的权利。
