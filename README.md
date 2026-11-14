# dnstake

子域名接管（subdomain takeover）检测器。它只评估**别人预先观察好的** DNS/HTTP 结果，
整个程序**不发起真实 DNS 查询、不发起真实 HTTP 请求、也不跟随任何重定向**。
仅使用 Python 标准库，无任何第三方依赖。

## 运行

    python -m dnstake.cli --observations demo/observations.json --out out/report.json

命令跑完后会在 stdout 打印一行摘要（域名数、可接管数、中风险数、可接管平台分布、涉及账号数），
并把完整报告写到 --out 指定的 JSON 文件。同一份输入跑两次，输出逐字节一致。

测试（在 tests/ 目录下运行）：

    cd tests && python -m unittest test_dnstake -v

## 观察数据格式

输入文件顶层是一个对象，domains 是一个数组，每个元素描述一个域名：

| 字段 | 含义 |
| --- | --- |
| domain | 域名本身 |
| ns | NS 条目数组，每条含 name 与 resolves（该 NS 域名自己能否解析出地址）；没有 NS 就是空数组 |
| cname_chain | CNAME 链，顺序是从第一个 CNAME 目标到最后一个目标；没有 CNAME 就是空数组。链的最后一环是最终目标 |
| a | 最终解析到的地址：无链时是域名自己的 A 记录，有链时是链尾目标的 A 记录；没有地址就是空数组 |
| http | 对该域名的一次 HTTP 观察，没观察过就是 null；有观察时含 status、body、location（location 没有就是 null） |

## 规范化规则

### 主机名规范化

域名自己、CNAME 链里的每一环、NS 名字、平台域名后缀，在参与比较之前都要：

1. 去掉首尾空白
2. 转成小写
3. 去掉末尾那个点（DNS 全称主机名结尾的根点）

### 响应正文规范化

按下面的顺序执行，顺序不能换：

1. 去掉成对尖括号连同中间的内容（HTML 标签）
2. 解码 HTML 实体：&amp; → &，&lt; → <，&gt; → >，&quot; → "，&apos; → '
3. 把所有连续空白（空格、制表符、换行）压成一个空格
4. 去掉首尾空格
5. 转成小写

规范化之后才做子串包含判断；平台表里的指纹子串也按同样顺序规范化后再比。
因为先去标签再解实体，正文里写成 &lt;b&gt; 的内容解出来是文本 <b>，不会被当成标签去掉。

## 已知托管平台表

| 平台 id | 域名后缀 | 期望状态码 | 正文指纹子串 |
| --- | --- | --- | --- |
| github-pages | github.io | 404 | there isn't a github pages site here. |
| heroku | herokuapp.com | 404, 503 | no such app |
| netlify | netlify.app | 404 | page not found |
| surge | surge.sh | 404 | project not found |
| bitbucket | bitbucket.io | 404 | repository not found |
| shopify | myshopify.com | 404 | sorry, this shop is currently unavailable |

某个主机名落在平台上：它等于平台域名后缀，或者以一个点加该后缀结尾。

## 可抢注账号名推导

链尾落在某个平台上时，取链尾中平台域名后缀前面紧挨着的那一段作为要抢注的平台账号名
（例如 user.github.io → user）。链尾正好等于平台域名后缀时没有账号名——
平台根域名不是谁都能注册的，一律不算可接管。

## 判定规则

### 解析环（unresolved / unknown）

CNAME 链里出现重复的名字就是解析环（绕回域名自身也算），判 unresolved、风险 unknown，
不得当成可接管。

### 可接管（takeover / high）

五个条件同时成立：

1. 链尾落在已知平台上，并且能取出可抢注的账号名
2. 最终解析到的地址为空
3. 有 HTTP 观察
4. 状态码不在 300–399 之间（工具不跟随重定向；location 只作为证据写进 evidence）
5. 状态码在该平台的期望状态码集合里，且规范化后的正文包含规范化后的平台指纹子串

平台域名本身不是证据：落在平台上但状态码对不上或指纹没命中，一律判 normal；
最终目标还有地址说明站点还开着，也判 normal。

### 悬空记录（dangling / medium）

同时满足：最终解析不到任何地址，并且没有任何可用委派——
CNAME 链为空，且 NS 条目为空或者所有 NS 的 resolves 都是 false。

NS 条目存在但 resolves 为 false 的算失效 NS，会在 evidence 里点名那个 NS 域名；
失效 NS 本身不构成高风险。

### 其余（normal / none）

不满足以上任何一条的判 normal，风险 none。

## 报告格式

报告顶层三个键：domains、findings、summary。

domains 里每条正好九个字段：

| 字段 | 含义 |
| --- | --- |
| domain | 规范化后的域名 |
| verdict | takeover / dangling / unresolved / normal |
| risk | high / medium / unknown / none |
| provider | 平台 id，只在判 takeover 时给出，其余为 null |
| claimable | 可抢注的账号名，只在判 takeover 时给出，其余为 null |
| chain | 规范化后的 CNAME 链（数组，按顺序，判 normal 的也如实给出） |
| normalized_body | 规范化后的响应正文，没有 HTTP 观察时为 null |
| matched_fingerprint | 命中的平台指纹子串（照平台表原样给出），没命中为 null |
| evidence | 证据文字：写明 NS 情况、CNAME 目标、A 记录、HTTP 状态码（重定向带 location），失效 NS 点名 |

findings 里一条对应一个判定结果不是 normal 的域名，每条含 domain、verdict、risk 三个字段。

summary 含八个字段：domains（域名总数）、takeover、dangling、unresolved、normal、
by_provider（平台 id 到条数，只统计 takeover）、by_risk（风险名到条数）、
accounts（判 takeover 的域名涉及的不同账号名数量——多条域名共用同一个链尾只算一个账号）。

## 代码结构

| 文件 | 职责 |
| --- | --- |
| dnstake/hosts.py | 主机名规范化 |
| dnstake/fingerprint.py | 正文规范化与指纹包含判断 |
| dnstake/providers.py | 平台表、平台匹配、账号名推导 |
| dnstake/chain.py | CNAME 链规范化与解析环检测 |
| dnstake/verdict.py | 单域名判定与证据生成 |
| dnstake/report.py | 报告组装（domains / findings / summary）与确定性序列化 |
| dnstake/cli.py | 命令行入口 |
| dnstake/__main__.py | python -m dnstake 入口 |
| demo/observations.json | 演示用观察数据（14 条） |
| tests/test_dnstake.py | 覆盖全部判定口径的 unittest |
