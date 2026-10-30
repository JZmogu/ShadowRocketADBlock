# ShadowRocketADBlock（adkit）

Shadowrocket 手机端去广告：主打 App 开屏广告 + 应用内嵌广告。自动融合多个社区优质规则源，去重合并后由 GitHub Actions 定时构建，**导入一次，之后自动/每周更新，不用再碰 GitHub**。

> 本项目是规则聚合管线，不生产规则，**也不处理你的代理节点**（节点信息绝不进入本公开仓库）。上游致谢见文末。产物不含任何 CA/私钥，HTTPS 解密使用你设备自己的证书。

## 用法一（推荐）：拆分接入——「规则」页放规则文件 + 「模块」页放开屏改写模块

Shadowrocket 同一时刻只有一份"主配置"。**不要把本仓库的 conf 导入成订阅，否则你的机场节点会被顶掉。**正确姿势（两处各加一条，机场配置完全不动）：

1. **开 HTTPS 解密并装自己的证书**：Shadowrocket → HTTPS 解密 → 生成根证书 → 安装 → 信任（设置→通用→关于本机→证书信任设置里全部打勾）。本订阅不携带任何证书。
2. **「规则」页 → 创建规则/远程规则**，粘贴：
   `https://raw.githubusercontent.com/JZmogu/ShadowRocketADBlock/dist/adkit-adonly.conf`
   （约 10.7 万条域名级广告拦截 + 放行兜底，SR 规则页专为大文件设计，自动更新）
3. **「模块」页 → 添加模块**，粘贴：
   - 你自己（每日自动更新）：`https://raw.githubusercontent.com/JZmogu/ShadowRocketADBlock/dist/latest/adkit-lite.module`
   - 朋友用（每周二钉版，稳）：`https://raw.githubusercontent.com/JZmogu/ShadowRocketADBlock/dist/stable/adkit-lite.module`
4. 两处开关都打开。节点、策略、机场订阅不受任何影响。

> GitHub 打不开时用 jsDelivr 镜像导入（仅首次，把 `raw.githubusercontent.com/JZmogu/ShadowRocketADBlock/dist/` 换成 `cdn.jsdelivr.net/gh/JZmogu/ShadowRocketADBlock@dist/`）。
> 一次性替代方案：`latest/adkit.module` / `stable/adkit.module`（规则+改写+MITM 合一的大模块，约 4MB——部分旧版 SR 对超大模块支持不佳，优先用上面的拆分法）。
> 真机请验证：规则页条数正常显示、模块开关打开后日志出现 `REJECT`、机场节点正常。若个别 SR 版本把模块规则排在主配置规则之后导致不生效，拆分法天然规避（规则页优先级由你手动排序）。

## 用法二：整份订阅（只有当你不需要代理节点时）

纯直连去广告（手机不需要翻墙，SR 全局选"直连"）时，才把整份配置导入为订阅：

| 通道 | 链接 | 说明 |
|---|---|---|
| **stable（推荐给朋友）** | `https://raw.githubusercontent.com/JZmogu/ShadowRocketADBlock/dist/stable/adkit.conf` | 每周二自动钉版，平时不变，稳 |
| latest（尝鲜） | `https://raw.githubusercontent.com/JZmogu/ShadowRocketADBlock/dist/latest/adkit.conf` | 每日自动更新 |

之后 SR 通过配置里的 `update-url` 自动检查更新，**无需任何手动操作**。
另有 `dist/adkit-adonly.conf`（纯 [Rule] 段）可作为"规则"页的远程子规则使用（不含开屏改写/MITM，功能不完整，仅备用）。

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
- [huijingfei/Shadowrocket-Rules](https://github.com/huijingfei/ShadowRocket-Rules)（无许可证：仅收录 [Rule] 段与开屏改写并全程注明出处；作者如有异议，提 issue 即剔除）
- [akiralereal/shadowrocket-toolkit](https://github.com/akiralereal/shadowrocket-toolkit)（GPL-3.0）与 [deezertidal/shadowrocket-rules](https://github.com/deezertidal/shadowrocket-rules)：开屏/内嵌 API 改写条目按出处人工精选钉版引用（每条在 `config/rewrite.toml` 标注 src 与日期）

## 已验证覆盖的常用 App 家族（2026-10-29）

微博系 / 小红书系 / 阿里系（淘宝、闲鱼、1688、淘宝闪购·饿了么、大麦、飞猪、淘票票）/ 腾讯系（QQ、微信、QQ音乐）/ bilibili（含漫画）/ 网易系（邮箱大师、有道、网易云音乐）/ 美团系（美团、外卖、猫眼）。
每个家族的**核心服务域**全部在 DIRECT 放行区并有金丝雀锁（被任何源拦截即阻止发布），**广告接口/素材域**按域名级 REJECT + API 级改写（开屏、弹窗、营销图、埋点）双层处理。误杀反馈走 issue。

本仓库代码与管线按 GPL-3.0 发布；规则内容版权归各上游所有，仅供个人学习使用。

## 免责声明

规则来自第三方社区源，本项目只做聚合与质量检查，不保证无误杀/无漏杀；使用订阅即同意自担风险。任何上游源可随时通过 issue 要求剔除。
