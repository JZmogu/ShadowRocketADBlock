# ShadowRocketADBlock（adkit）

适用于 Shadowrocket 的广告拦截规则和 URL 改写，提供 stable 与 latest 两个更新通道。规则出处与许可证见文末；产物不携带 CA 或私钥，HTTPS 解密使用你设备自己的证书。

配置能导入，不代表所有广告请求都已被拦截。现有规则针对登记的域名或接口；微博、B站、美团的信息流，QQ/微信内嵌内容，以及淘宝、京东的自动直播，可能通过未覆盖的接口或正常业务响应下发。规则登记的合成 URL 样例用于回归检查，不能据此宣称某个 App 已经真机验证或所有广告均可去除。

## 推荐：在现有主配置中添加模块

已有机场配置、节点和分流策略时，优先使用模块，无需另选一份主配置。Shadowrocket 同一时刻使用一份主配置；导入本项目的完整 conf 不会自动合入你原配置的分流设置。

| 通道 | 模块链接 | 服务端发布计划 |
|---|---|---|
| stable | `https://raw.githubusercontent.com/JZmogu/ShadowRocketADBlock/dist/stable/adkit.module` | 每周二 |
| latest | `https://raw.githubusercontent.com/JZmogu/ShadowRocketADBlock/dist/latest/adkit.module` | 每日 |

1. 在“配置”页确认你原本的主配置仍被勾选，然后打开该配置的“模块”页面，添加上面的模块链接并启用。
2. 返回**当前勾选的主配置**，进入 ⓘ → HTTPS 解密，生成或选择你自己的 CA 证书并安装。到 iOS 设置 → 通用 → VPN 与设备管理完成描述文件安装，再到通用 → 关于本机 → 证书信任设置，只开启你安装的这张证书的信任。
3. 回到同一份主配置，确认 HTTPS 解密开关已开启。安装、信任证书与打开解密开关是三个不同步骤；换主配置后需要重新确认。模块只追加 MITM hostname，不代替主配置的解密开关或设备证书。
4. 测试时将首页“全局路由”设为“配置”，保持 Shadowrocket 连接，然后重新发起目标 App 的请求。

模块的 MITM hostname 使用 `%APPEND%` 追加到主配置。模块规则仍可能影响已有路由或与其他模块冲突，尤其用户自定义 DIRECT 规则；出现异常时先禁用本模块做对照，再检查实际命中规则。

Shadowrocket 的 URL REJECT 改写默认在“配置”路由模式生效。如果需要在全局代理等模式也应用 URL REJECT，可在自己的主配置 `[General]` 中设置 `always-reject-url-rewrite = true`。这不表示域名拦截规则在所有模式都生效，也不能替代 HTTPS 解密。

## 可选：导入完整配置

需要独立使用本项目规则时，在“配置 → 下载配置”导入以下链接，**勾选导入后的配置**，再按照上面的证书步骤为这份配置启用 HTTPS 解密。测试仍使用“全局路由 → 配置”；节点通过 Shadowrocket 自身管理，完整配置不会自动继承原主配置的策略。

| 通道 | 配置链接 |
|---|---|
| stable | `https://raw.githubusercontent.com/JZmogu/ShadowRocketADBlock/dist/stable/adkit.conf` |
| latest | `https://raw.githubusercontent.com/JZmogu/ShadowRocketADBlock/dist/latest/adkit.conf` |

完整配置设置了 `always-reject-url-rewrite = true`，但启用的文件、节点、证书信任与解密状态仍需在设备上确认。另有 `dist/adkit-adonly.conf`，只含域名/IP 等路由规则，不含人工 URL 改写或解密配置。

服务端计划在北京时间每日 09:00 发布 latest，每周二 09:00 发布 stable；实际时间受 GitHub Actions 调度和检查结果影响。客户端刷新时间取决于 Shadowrocket 版本和更新设置，可手动更新当前配置或模块，并核对文件中的构建时间。GitHub 无法访问时，首次导入可使用对应 jsDelivr 镜像，例如 `https://cdn.jsdelivr.net/gh/JZmogu/ShadowRocketADBlock@dist/stable/adkit.module`，并注意 CDN 缓存可能延迟。

## 能导入，但广告还在时

先确认当前配置已勾选、模块已启用、连接已开启，并在“配置”路由模式测试。需要看 HTTPS 路径时，确认当前配置的解密开关与对应证书信任；不要仅以系统中存在一张证书判断已生效。

在 Shadowrocket 的“数据 → 代理”中启用日志，重新打开目标 App 并触发广告，再查看这次请求的 URL、主机名和命中策略。记录显示 `MITM` 才能说明该请求域名启用了解密；只有域名而没有路径时，不应据此判断 URL 改写是否命中。还要区分已经缓存的广告与新下载内容。

反馈时提供 App 名称和版本、广告位置、stable/latest、文件构建时间、是否显示 MITM，以及去掉 Cookie、Token、账号等内容后的请求路径与命中规则。若请求根本未命中当前规则，就需要针对实际接口补规则；若广告与正常内容共用响应，简单拒绝整个接口可能影响正常功能，需要另外评估响应内容处理，不能一律拉黑业务域名。

## 规则维护与自我构建

域名误杀可通过 `config/whitelist.txt` 增加 DIRECT 例外；自定义域名/IP 规则放在 `config/user_rules.txt`。URL 改写误杀需要调整或禁用 `config/rewrite.toml` 中对应条目，域名白名单不等于关闭 HTTPS 改写。修改在下一次成功构建发布后生效。

`config/rewrite.toml` 手工维护改写、出处、应匹配的 `example_urls` 和不应匹配本条规则的 `allow_urls`。构建检查正则、动作、样例匹配和 HTTPS 样例的 MITM 覆盖；这些输入不能代表所有真实请求。当前“淘宝视频广告”规则覆盖 `cloud.video.taobao.com/vod/` 下的 MP4，可能包含非广告视频，并与 alimama 视频规则重叠；需要保留此类视频时，可禁用这一条并根据实际 URL 调整。该规则不代表能够关闭所有自动直播。

```sh
python main.py build           # 抓取并构建，产物在 dist/
python main.py build --offline # 使用本地有效快照/缓存
python main.py explain 某域名  # 查询本地规则；也可传入 URL 或 IP
python -m unittest discover -s tests -q
```

使用 Python 3.11+ 标准库，无第三方运行依赖。下载地址、开关和单源健康阈值在 `config/sources.toml`。下载或内容校验失败时尝试有效本地快照，没有可用副本或后续检查失败则停止发布。全部质量检查成功后才更新有效快照；CI 将其随产物保存到 dist，并在下次构建前恢复快照与历史统计。

域名金丝雀和代表性正常 URL 用来发现登记范围内的误拦，不会自动创建 DIRECT 规则，也不能证明所有子域名、路径或 App 版本正常。`explain` 查询本地配置与数据，不代表手机上已经使用了这个版本；它无法复现客户端证书状态、网络协议、缓存或 App 的实际请求。

## 上游致谢与许可证

- [Johnshall/Shadowrocket-ADBlock-Rules-Forever](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever)（CC BY-SA 4.0，仅取 ad_only 段）
- [privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD)（MIT）
- [TG-Twilight/AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule)（GPL-3.0，秋风 AWAvenue）
- [huijingfei/Shadowrocket-Rules](https://github.com/huijingfei/ShadowRocket-Rules)（无许可证：仅收录 [Rule] 段与开屏改写并全程注明出处；作者如有异议，提 issue 即剔除）
- [akiralereal/shadowrocket-toolkit](https://github.com/akiralereal/shadowrocket-toolkit)（GPL-3.0）与 [deezertidal/shadowrocket-rules](https://github.com/deezertidal/shadowrocket-rules)：开屏/内嵌 API 改写条目按出处人工精选钉版引用（每条在 `config/rewrite.toml` 标注 src 与日期）

本仓库代码与管线按 GPL-3.0 发布，规则内容版权归各作者所有，不保证无误杀或漏杀。
