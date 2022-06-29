## 介绍

​	Splunk 对接微步在线API接口查询IP或者域名是否为恶意

## 在哪里安装

| Splunk Node         | What to install |
| ------------------- | --------------- |
| Search Head         | √               |
| Indexer             | ×               |
| Heavy Forwarder     | ×               |
| Universal Forwarder | ×               |



## 安装App

![image-20220629232705750](https://hescinfo-images.oss-cn-shenzhen.aliyuncs.com/image-20220629232705750.png)

![image-20220629232808975](https://hescinfo-images.oss-cn-shenzhen.aliyuncs.com/image-20220629232808975.png)



## 使用方法

- **IP查询例子：**

```sql
| makeresults count=1 
| eval src="1.1.1.1"
| tip field=src type="ip" apikey="xxx***xxx"
```

- **IP和域名混合查询例子：**

```sql
# IP地址
| makeresults count=1 
| eval src="1.1.1.1"
| tip field=src type="collapse" apikey="xxx***xxx"

# 域名
| makeresults count=1 
| eval src="example.com"
| tip field=src type="collapse" apikey="xxx***xxx"
```

