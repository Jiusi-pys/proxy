# Surge 服务规则

从实际使用的 Surge Mac 配置提取，按 52 个服务或基础设施类别维护。公共部分包含 60 个 `.list`，适用于 Surge Mac；保留 `extended-matching`、`no-resolve`、进程及协议规则的原始语义。

- `*.list`：无策略名的外部 RULE-SET；同服务可同时包含域名、网段或进程条件。
- `rules.conf`：只含 `[Rule]` 的远程引用片段，不是完整配置。使用前在私有配置定义其中的策略组。
- `manifest.json`：服务、策略、选项和公共条目数。特定设备地址已排除，不能由此还原完整私人配置。

## 顺序与隐私

只合并连续、同服务、同策略、同选项的规则。同一服务跨位置或选项不同，使用 `-part02` 等分段文件，避免跨过优先级例外。Apple 新闻/视频例外仍先于 Apple 直连；Gemini 仍先于 Google 通用规则。

局域网文件仅包含通用保留网段。特定设备地址应保留在私有 Profile 中，放在 IPv4 与 IPv6 列表之间。节点、订阅 URL、控制密钥、MITM 证书和完整 Profile 不属于本目录，禁止提交。

公共片段使用 `jiusi` 分支远程链接。实际部署可将 URL 中的 `refs/heads/jiusi` 换成经过验证的 Git commit SHA，以固定规则版本；更新时核对新版本再替换 SHA。

## 验证与维护

`python3 scripts/organize_active_surge.py /path/to/private-profile.conf --output /path/to/private-staging/profile.conf` 可从未拆分的配置生成候选列表；它不会自动部署、发布或重新加载。生成内容仍需检查私人设备地址等信息，不能未经检查就提交。

执行 `python3 -m unittest discover -s tests -p test_service_organization.py -v` 验证服务归类边界。使用 Surge 自带 `surge-cli --check` 校验完整候选配置，再执行 `reload`，检查 `external-resource list` 和 `rule match`。

初次本地迁移通过 Surge Mac 6.9.1 配置检查和 42 个无连接策略对比。上线远程链接时，还应逐个核对下载内容、确认资源加载，并复查策略和实际 HTTP 请求。本目录不是 Mihomo YAML；Surge iOS 不支持其中的 Mac 进程规则。
