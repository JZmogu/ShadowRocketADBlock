# ShadowRocketADBlock（adkit）

Shadowrocket 手机端去广告**一键订阅**：主打 App 开屏广告 + 应用内嵌广告。自动融合多个社区优质规则源，去重合并后由 GitHub Actions 定时构建，**导入一次，之后每周自动更新，不用再碰 GitHub**。

> 本项目是规则聚合管线，不生产规则。上游致谢见文末。产物不含任何 CA/私钥，HTTPS 解密使用你设备自己的证书。

## 一键订阅（两个通道）

| 通道 | 链接 | 说明 |
|---|---|---|
| **stable（推荐给朋友）** | `https://raw.githubusercontent.com/JZmogu/ShadowRocketADBlock/dist/stable/adkit.conf` | 每周二自动钉版，平时不变，稳 |
| latest（尝鲜） | `https://raw.githubusercontent.com/JZmogu/ShadowRocketADBlock/dist/latest/adkit.conf` | 每日自动更新 |

打不开 GitHub 时，导入阶段可用 jsDelivr 镜像（仅用于首次导入；自动更新走上面的正链）：
`https://cdn.jsdelivr.net/gh/JZmogu/ShadowRocketADBlock@dist/stable/adkit.conf`

## 给朋友的三步（一次性，之后全自动）

1. **开 HTTPS 解密并装自己的证书**：Shadowrocket → HTTPS 解密 → 生成根证书 → 安装 → 信任（设置→通用→关于本机→证书信任设置 里全部打勾）。这一步只影响你自己的设备，本订阅不携带任何证书。
2. **导入订阅**：Shadowrocket → 配置 → 下载配置 → 粘贴上面的 stable 链接。
3. **加你自己的节点**：在"订阅"里添加你自己的机场订阅即可，与本配置互不干扰。

之后每周二早上，SR 会通过配置里的 `update-url` 自动检查更新，**无需任何手动操作**。

## 发现误杀怎么办

手机记下被误杀的域名 → 在本仓库提 issue（或改 `config/whitelist.txt` 发 PR）→ 下次构建起该域名永久 DIRECT 放行。构建有金丝雀域名测试与上游异常隔离，坏版本不会推给你（自动沿用上一次的版本）。

## 覆盖内容与原理

- 域名级拦截（App 内嵌广告/追踪的静态资源与接口域名）：融合 Johnshall、anti-AD、AWAvenue（秋风）、huijingfei 四个源，L1 精确去重 + L2 子域吸收。
- 开屏广告 API 级改写（需要第 1 步的 HTTPS 解密）：精选登记表 `config/rewrite.toml`，目前含 B站/知乎/京东/淘宝/闲鱼/高德/网易云/58 等开屏与弹窗接口，用 `REJECT-DICT`（返回空 JSON，App 不卡死）等 Shadowrocket 原生动作。
- 全部人工精选：改写规则不会自动跟随上游，改动都需经过金丝雀测试。

## 自我构建（给自己）

```
python main.py build          # 抓取+构建，产物在 dist/
python main.py explain 某域名  # 查询某域名被哪条规则命中/放行
python -m unittest discover -s tests -q
```
零第三方依赖（Python 3.11+ 标准库）。源开关在 `config/sources.toml`。

## 上游致谢与许可证

- [Johnshall/Shadowrocket-ADBlock-Rules-Forever](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever)（CC BY-SA 4.0，仅取 ad_only 段）
- [privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD)（MIT）
- [TG-Twilight/AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule)（GPL-3.0，秋风 AWAvenue）
- [huijingfei/Shadowrocket-Rules](https://github.com/huijingfei/Shadowrocket-Rules)（无许可证：仅收录 [Rule] 段与开屏改写并全程注明出处；作者如有异议，提 issue 即剔除）

本仓库代码与管线按 GPL-3.0 发布（LICENSE 待补全文）；规则内容版权归各上游所有，仅供个人学习使用。

## 免责声明

规则来自第三方社区源，本项目只做聚合与质量检查，不保证无误杀/无漏杀；使用订阅即同意自担风险。任何上游源可随时通过 issue 要求剔除。
