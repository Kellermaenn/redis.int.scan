# redis
redis scan

redis 是用来检测服务器的redis服务是否存在未经授权访问的漏洞

工作原理
1、指定ip地址，扫描指定ip，掩码24的ip地址范围的redis
2、多线程扫描

用法示例
redis.py -i 210.123.123.123 -t 10
