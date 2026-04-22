# OClash Rules Auto Builder

这个仓库现在支持通过 **GitHub Actions + Python** 自动更新规则，保持你现有发布文件名不变（`NewRule.ini` 可继续直接使用）。

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
