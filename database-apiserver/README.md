```console
$ go run database-apiserver/main.go
2019/01/02 18:09:45 listening on 127.0.0.2:8443

$ curl -k https://127.0.0.2:8443/database/postgres
Resource: postgres
$ curl -k https://127.0.0.2:8443
OK
```
