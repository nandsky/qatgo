# QAT_GO
QAT密码服务项目


## 介绍
### QATGO
远程加解密服务，支持TCP协议调用，或grpc调用

TCP端口：  50051

GRPC端：   50053

### CAPI
对QAT卡的CPA接口封装，面向GO语言的调用

### CryEngine
OpenSSL引擎，通过网络远程调用QATGO来达到加解密目的


## Installation

## 算法支持
        ssl_protocols   TLSv1 TLSv1.1 TLSv1.2;
        ssl_ciphers RC4+RSA:AES128+RSA:HIGH:!aNULL:!MD5;
        ssl_session_timeout 10m;
        ssl_certificate          /usr/local/servers/nginx/conf/domains/keys/demo.pem;
        ssl_certificate_key          /usr/local/servers/nginx/conf/domains/keys/demo.pem;

## See also
- [Intel QAT](https://01.org/intel-quickassist-technology)
- [QAT OpenSSL Engine](https://github.com/01org/QAT_Engine)
