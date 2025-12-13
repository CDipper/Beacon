# 简单重构Beacon  With C 

此项目是适配CobaltStrike客户段的重构的Beacon（x64）。需要使用到提供的profile（beacon.profile），此profile主要是对通信流量进行了一些处理（编码，prefix、suffix等）。

所有的情况都是针对CobaltStrike 4.4客户端，在更高的CobaltStrike版本上没有进行测试。同时此项目的Beacon仅是一个简单的载荷，不及CobaltStrike的扩展性。我觉得它具有一定的免杀性，如果可以，你能够进行一些功能的扩展以及防御的规避。

![image-20251020142632555](README.assets/image-20251020142632555.png)

## 实现的功能

- [x] sleep
- [x] filebrowse
- [x] upload
- [x] drives
- [x] mkdir
- [x] pwd
- [x] getuid
- [x] ps
- [x] rm
- [x] download
- [x] shell
- [x] exit
- [x] inline-execute
- [x] screenshot
- [x] keylogger
- [x] hashdump
- [x] dllinject
- [x] getprivs
- [x] inject（注入 x64、x86都实现了）
- [x] setenv
- [x] cp
- [x] cd
- [x] mv
- [x] execute-assembly
- [x] jobs
- [x] jobkill

## 快速开始

- **克隆项目代码**

  ```bash
  git clone https://github.com/CDipper/Beacon
  ```

- **配置你的C2信息**

  在 `Config.c` 中填写你的 C2 服务器地址及Listener端口。

- **配置RSA公钥**

  在`Config.c`中将RSA公钥替换为你自己的（PEM格式），或者直接使用 项目提供的`.cobaltstrike.beacon_keys` 文件作为私钥，并将其替换到 CobaltStrike客户端中。

- **编译**

  Debug + x64编译即可，没有任何第三方库。

- **运行**

  双击编译成功的程序，即可上线你的CobaltStrike客户端。

- **Teamserver启动**

  启动teamserver带上此项目提供的profile即可。

演示如下：

https://github.com/user-attachments/assets/a59dc77f-3ca2-47c5-bb1d-0d1e857857ba




## ToDo

- [x] 使用Beacon内部API进行数据解析

- [x] 当Beacon连接不到Server时，重复进行尝试，每次失败后，睡眠一段时间

- [ ] 对于一些交互式shell命令（time），造成命令等待输入阻塞问题

- [ ] 实现sleep jitter

- [ ] 隐藏windows terminal

- [ ] 错误日志重定位输出到文件

- [x] 对于Upload命令，当上传文件大于1MB时，CobaltStike Server会分段传输，然后循环发送剩余的数据，直至最后小于1MB左右的数据，对于的功能号为67

- [ ] 对于Upload命令，可以考虑使用线程来执行任务，不然主线程容易等待较长时间

## 其它

- 上传大文件（>几十MB）时，CobaltStrike客户端可能要读取解析文件，会造成长时间卡顿。
- 不支持profile解析（一大痛点）。
- 此Beacon中但凡涉及到进程注入的，都是注入到rundll32。

- 此Beacon的注入方式有CreateRemoteThread以及SetThreadContext&ResumeThread，对于创建进程采用后者，注入到已有进程采用前者，追求opsec，可以实现更加隐蔽的进程注入方法（线程池注入、无线程注入等）。
- screenshot、keylogger、hashdump功能，都是使用CobaltStrike已有的Dll，若追求opsec，可以自己实现这两个功能Dll。研究一下CobaltStike是如何patch命令管道的。
- inject命令进行Beacon迁移时，也是使用CobaltStrike客户端自带的原始`beacon.dll`，可以自行修改CobaltStrike客户端进行Dll替换。
- 仅支持x64，仅测试了Debug模式。

## 免责声明

- 本仓库仅用于**学术研究、教育与防御能力评估**。
- 请在**授权且隔离的实验环境**中运行任何攻击相关测试脚本。禁止将本项目用于任何未授权的入侵测试或非法行为。作者对任何因误用本项目导致的法律后果不承担责任。
- **仅供学习研究使用，严禁用于非法用途。** 
