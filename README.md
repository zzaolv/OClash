# OClash Rules Auto Builder

这个仓库现在支持通过 **GitHub Actions + Python** 自动更新规则，保持现有发布文件名不变（`NewRule.ini` 可继续直接使用）。

## 目标

- 保留现有产物文件名（例如 `GWAI.list` / `GWAI.mrs`）
- 自动拉取多个上游规则
- 统一规范化、去重、裁剪后输出
- 支持 `custom/*.add.list` 与 `custom/*.del.list` 自定义增删
- 定时自动提交更新

## 自动化入口

- 工作流：`.github/workflows/update-rules.yml`
- 构建脚本：`scripts/build_rules.py`
- 配置文件：`rules-config.json`

## 当前产物与职责

- `GWAI.list` + `GWAI.mrs`：AI 相关规则（OpenAI/Claude 等）
- `GW.list` + `GW.mrs`：通用代理
- `CN.list` + `CN.mrs`：国内直连
- `others.list` + `others.mrs`：兜底规则
- `ProxyMedia.list` + `ProxyMedia.mrs`：流媒体代理
- `CNIP.mrs` / `GWIP.mrs` / `ProxyMediaIP.mrs`：IP-CIDR 规则集

## 自定义覆盖

可通过 `custom/` 目录注入你的自定义：

- `custom/GWAI.add.list`
- `custom/GWAI.del.list`
- `custom/GW.add.list`
- `custom/GW.del.list`
- `custom/CN.add.list`
- `custom/CN.del.list`
- `custom/others.add.list`
- `custom/others.del.list`

处理顺序：

1. 上游合并
2. 规范化
3. 去重
4. 应用 add
5. 应用 del
6. 再次去重并输出

## 如何本地运行

```bash
python scripts/build_rules.py
```

## GitHub Actions 调度

`update-rules.yml` 支持：

- `workflow_dispatch`（手动触发）
- `schedule`（每 6 小时）

工作流会在有变更时自动提交。

## 说明

- `.list` 为文本规则输出（classical）
- `.mrs` 当前采用上游成熟产物直连下载，减少二进制编译链不稳定因素
- 如后续需要本仓库自行编译 `.mrs`，可在 `build_rules.py` 基础上扩展 mihomo 转换步骤

## AdGuard Home 合并规则

把 AdGuard Home 里订阅的多个过滤列表合并成一个文件，每天自动更新。

- 订阅地址：`https://raw.githubusercontent.com/zzaolv/OClash/adguard/adguard.txt`
- 工作流：`.github/workflows/update-adguard.yml`（北京时间每天 03:30，也可手动触发）
- 配置文件：`adguard/hostlist-compiler.json`，上游列表都写在这里
- 合并工具：AdGuard 官方的 [HostlistCompiler](https://github.com/AdguardTeam/HostlistCompiler)

处理步骤：

1. 下载各上游列表，hosts 格式和纯域名统一转成 `||域名^`
2. 白名单订阅（8680 allow）转成 `@@` 放行规则一起合并
3. 去掉 AdGuard Home 用不上的规则：浏览器元素隐藏规则、只对某些网站生效的规则、不支持的修饰符、整个顶级域名的拦截
4. 去重，并去掉已被父域名规则覆盖的子域名规则（有 `||example.com^` 就不再需要 `||ads.example.com^`）
5. 应用 `custom/adguard.del.txt` 里的剔除规则，追加 `custom/adguard.add.txt` 里的自定义规则

保护措施：

- 任何一个上游下载失败，或者结果少于 15 万条，本次都不发布，AdGuard Home 继续用上一版
- 结果发布在单独的 `adguard` 分支，每次覆盖成一个提交，不会让 main 的历史越来越大
- 改动规则配置的 PR 只编译检查、不发布，编译结果可以在该次运行的 Artifacts 里下载

自定义：

- `custom/adguard.add.txt`：追加规则，AdGuard 语法，例如 `||example.com^`、`@@||example.com^`
- `custom/adguard.del.txt`：剔除规则，写规则原文，或通配符、`/正则/`；默认剔除了会拦掉所有反向解析的 `||in-addr.arpa^` 和 `||ip6.arpa^`

AdGuard Home 里自己写的「自定义过滤规则」不受影响，继续在 AdGuard Home 里维护。
