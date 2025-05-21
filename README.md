# file-aes
大文件aes加密


# 使用
## 加密
```shell
go run main.go  -e -k 0123456789abcdef0123456789abcdef -i C:\kong\m1.zip -o C:\kong\m1.enc 
```

## 解密
```shell
go run main.go  -d -k 0123456789abcdef0123456789abcdef -i C:\kong\m1.enc -o C:\kong\m1.zip 
```