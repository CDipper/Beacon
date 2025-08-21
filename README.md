# 重构Beacon  With C 

此项目是适配CobaltStrike客户段的重构的Beacon。需要使用到提供的`beacon.profile`。

![image-20250727213547898](README.assets/image-20250727213547898.png)

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
- [ ] screenshot
- [ ] keylogger
- [ ] dllinject

## Bug

开发过程中测试发现的Bug：

- [x] drivers命令崩溃
- [ ] upload上传大文件时，AES解密出错，解密数据不为16的倍数
- [ ] upload上传大文件时，崩溃
- [x] shell执行calc时崩溃

## ToDo

- [x] 不使用buff_init、buffer_append、buffer_free
- [ ] 重写ps命令
- [ ] 对于一些交互式shell命令（time），造成命令等待输入阻塞问题

