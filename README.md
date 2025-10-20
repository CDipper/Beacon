# 简单重构Beacon  With C 

此项目是适配CobaltStrike客户段的重构的Beacon。需要使用到提供的`beacon.profile`，此profile主要是对通信流量进行了一些处理（编码，prefix、suffix等）。

下面所有的情况都是针对CobaltStrike 4.4客户端。

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
- [ ] hashdump
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

## Bug

开发过程中测试发现的Bug：

- [x] drivers命令崩溃
- [x] AES有些时候解密出错，解密数据大小不为16的倍数
- [x] shell执行calc时崩溃
- [x] download命令无法成功下载
- [x] FileBrowse多次后会崩溃
- [x] execute-assembly回显数据有两份相同的（原因：注入了两次）

## ToDo

- [x] 不使用buff_init、buffer_append、buffer_free函数，容易造成崩溃

- [x] 使用Beacon内部API进行数据解析

- [x] 当Beacon连接不到Server时，重复进行尝试，每次失败后，睡眠一段时间

  ![image-20250824173438774](README.assets/image-20250824173438774.png)

- [ ] 对于一些交互式shell命令（time），造成命令等待输入阻塞问题

- [ ] 实现sleep jitter

- [ ] 隐藏windows terminal

- [ ] 错误日志重定位输出到文件

- [x] 对于Upload命令，当上传文件大于1MB时，CobaltStike Server会分段传输，然后循环发送剩余的数据，直至最后小于1MB左右的数据，对于的功能号为67

- [ ] 对于Upload命令，可以考虑使用线程来执行任务，不然主线程容易等待较长时间

![image-20250824160625301](README.assets/image-20250824160625301.png)

## 其它

- 上传大文件（>几十MB）时，CobaltStrike客户端可能要读取解析文件，会造成长时间卡顿
- 不支持profile解析（一大痛点）
- 此Beacon中但凡涉及到进程注入的，都是注入到rundll32

- 此Beacon的注入方式有CreateRemoteThread以及SetThreadContext&ResumeThread，对于创建进程采用后者，注入到已有进程采用前者
- screenshot、keylogger等功能，都是使用CobaltStrike已有的Dll，追求opsec，可以自己实现
- inject命令进行Beacon迁移，也是使用CobaltStrike自带的原始beacon.dll
