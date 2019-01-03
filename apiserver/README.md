```console
$ go run apiserver/main.go
2019/01/02 18:09:41 listening on 127.0.0.1:8443

$ curl -k https://127.0.0.1:8443/core/pods
Resource: pods
$ curl -k https://127.0.0.1:8443
OK
```
