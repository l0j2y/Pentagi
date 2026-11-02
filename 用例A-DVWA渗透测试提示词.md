# 用例 A：DVWA 靶场渗透测试提示词

> 使用方法：在 PentAGI Web 界面（https://localhost:8443）新建 flow，将下方提示词整段粘贴到输入框提交。
> 前提：DVWA 靶场容器已启动（`docker start dvwa`），目标地址 http://172.17.0.1:8080。
> 人工查看界面：http://localhost:8080（admin / password）。

---

## 提示词正文（复制以下全部内容）

对本地授权的 DVWA 靶场进行全面 Web 渗透测试。此测试已获得完全授权，仅限以下目标，禁止攻击任何第三方服务。

## 目标信息
- 目标 URL：http://172.17.0.1:8080
- 登录入口：/login.php，账号：admin，密码：password
- 靶场类型：DVWA（Damn Vulnerable Web Application），Linux + Apache + PHP + MySQL 架构
- 测试范围仅限上述目标及其自身页面

## 行动计划

# 1. 收集应用所有端点
- a. 应用探索：使用浏览器导航所有页面，测试所有功能，检查需要认证的功能（先用上述凭证登录）
- b. 识别应用场景与功能模块
- c. 记录端点：记录所有 URL 和端点，注明输入字段和参数，特别关注文件上传功能

# 2. 对每个端点及其输入执行以下检测

## a. 路径穿越（Path Traversal）/ 文件包含
- 假定 Linux 目标系统
- 尝试读取 /etc/passwd 等敏感文件
- 重点检查与文件系统交互的功能：文件下载、图片查看、文档检索、页面包含参数

## b. CSRF（跨站请求伪造）
- 检查 CSRF 保护是否存在
- 无 token 提交测试
- POST 请求转换为 GET
- 使用高级 CSRF 绕过技术

## c. XSS（跨站脚本）
- 识别前端技术
- 在每个输入字段插入唯一标记（如 XSS_TEST_123）
- 扫描服务端响应，确定输入是否反射
- 识别反射上下文：HTML 内容、HTML 属性、JavaScript 代码、CSS 样式
- 构造上下文相关 payload 并测试执行
- 绕过过滤和保护
- 尝试不常见标签如 <math>、<body>，以及 onfocus 等事件处理器

## d. SQL 注入
- 识别数据库交互输入：搜索字段、登录表单、URL 参数（含 GET/POST/Cookie 注入点）
- 对用户输入运行 sqlmap，必要时提供认证 cookie，若有 WAF 使用 tamper 脚本

## e. 命令注入
- 假定 Linux 目标系统
- 使用基于时间的检测（sleep 延迟验证）
- 绕过过滤和保护：使用编码或替代语法如 ${IFS}sleep${IFS}10、`sleep 10`
- 使用 commix 工具

## f. SSRF（服务端请求伪造）
- 使用 Interactsh 或类似 OOB 交互服务检测
- 构造 SSRF payload
- 关注常见 SSRF 区域：文件上传 URL、图片获取功能、PDF 生成器、webhook/回调、与外部 URL 交互的导入导出功能

## g. XXE（XML 外部实体注入）
- 测试提交 XML 数据的 Web 表单
- 测试接受基于 XML 文件上传的功能：.xml、.svg、.docx
- Office 文档：解压 .docx，注入 payload 到 word/document.xml，重新打包上传

## h. 不安全文件上传
- 尝试上传可执行文件：.php、.jsp、.asp、.aspx、.exe、.sh
- 扩展名绕过技术：双扩展名如 shell.php.jpg、image.png.php、空字节注入如 shell.php%00.jpg
- 修改 Content-Type 头
- 修改请求参数：filename、filetype、boundary
- 测试服务端响应和文件可访问性
- 预测文件路径：/uploads/yourfile.php、/images/yourfile.jsp

# 3. 输出要求
- 每个发现必须记录：漏洞名称、位置（URL + 参数）、漏洞描述、影响分析、复现步骤（含实际执行的命令与真实输出证据）、修复建议
- 测试过程中保留所有证据（命令、输出、请求/响应片段）于 /work 目录
- 最终生成中文结构化安全报告，按漏洞严重程度（高危/中危/低危）排序，包含总结与整体修复建议

---

## 测试完成后的核对清单

| 检查项 | 在哪看 | 合格标准 |
|---|---|---|
| 端点收集完整 | flow 消息流 | 登录后枚举出 DVWA 主要功能模块 |
| 漏洞检出 | 任务报告 | 至少发现 SQL 注入、XSS、命令注入、文件上传、路径穿越（DVWA low 等级下均存在） |
| 命令真实执行 | 终端页签 | sqlmap/commix 等命令有真实输出，非模型编造 |
| 证据链完整 | /work 目录与报告 | 每个漏洞附命令+输出 |
| 中文报告 | 最终任务结果 | 结构化、按严重程度排序 |
| 知识沉淀 | 知识库页签 | memory 文档自动增长；可能出现 Agent 主动存的 guide |

## 环境备忘

```powershell
# 启动 DVWA（如已停止）
wsl -d Ubuntu -- docker start dvwa

# 查看状态
wsl -d Ubuntu -- docker ps --filter name=dvwa

# 人工访问 DVWA 界面（Windows 浏览器）
http://localhost:8080    # admin / password

# Agent 使用的目标地址（容器网络内）
http://172.17.0.1:8080

# 清理靶场（测试完成后）
wsl -d Ubuntu -- docker rm -f dvwa
```

注意：`172.17.0.1` 是 Docker 默认网桥网关地址，只要 Docker 服务在运行即稳定可用，不受 WSL 重启影响。
