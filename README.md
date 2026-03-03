![SIPVicious mascot](https://repository-images.githubusercontent.com/32133566/55b41300-12d9-11eb-89d8-58f60930e3fa)

这个项目是一个基于 Python 开发的 SIP 安全审计集成工具。它将业界著名的开源 SIP 协议检测套件 SIPVicious 与图形化用户界面（GUI）进行了深度整合，旨在为安全研究人员提供一个直观、稳定且易于部署的扫描平台。

以下是该项目的核心组成部分与技术亮点：

🛠️ 核心功能模块
该工具完整集成了 SIPVicious 的三大核心能力：

探测 (SVMap)：用于在特定网段内搜索活跃的 SIP 设备，识别目标系统的 User Agent 信息（如截图所示，已成功识别出 SIP UAS V2.1.4.662543）。

扫号 (SVWar)：在发现 SIP 设备后，通过暴力枚举或顺序探测的方法找出目标服务器上注册的合法分机号。

审计 (SVCrack)：针对特定分机进行密码强度审计，支持数字范围枚举或自定义字典，帮助管理员发现弱口令风险。

🚀 技术架构与优化
相比于原始的命令行工具，本项目在稳定性和兼容性上做了大量深度优化：

内核动态适配引擎：
针对 sipvicious 不同版本间入口函数名不统一的问题（如 Main、main 或 run），项目内置了动态探测逻辑，确保在不同电脑环境下都能准确调用内核模块。

多流日志回显系统：
采用了统一的日志拦截器，同时捕获 sys.stdout（标准输出）、sys.stderr（标准错误）以及 Python 内置的 logging 模块输出。这解决了 GUI 运行脚本时常见的“界面无反应”或“输出乱跑到后台”的问题，实现了扫描进度的实时可视化。

线程安全 GUI 设计：
底层扫描逻辑运行在独立线程中，通过 root.after 异步更新 UI 队列，确保即使在高强度网段扫描时，程序界面依然流畅不卡死。


python -m PyInstaller --noconsole --onefile --name "SIP全能审计工具" --collect-all sipvicious --icon=logo.ico sip.py

