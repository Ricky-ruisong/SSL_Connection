# SSL_Connection

## 功能
1.SSL-TCP加密通讯的C语言实现<br/>
2.开辟子线程<br/>
3.互斥锁功能<br/>
4.计时器功能<br/>
5.时间戳功能<br/>
6.转化字符串<br/>

## 编译
切换至该文件夹，命令行键入make<br/>

## 测试客户端启动命令
./client IP地址 端口 用户数字证书路径 用户私钥路径<br/>
	比如:	./client xxx.xxx.xxx.xxx 52000 ./client.crt ./client.pem<br/>

### 注意
需要把ca.crt / client.crt / client.pem 均放置到该目录下<br/>
建立server端和client端通讯可参考上一篇文章<br/>
https://github.com/Ricky-ruisong/Instant-Messaging
