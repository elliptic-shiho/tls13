TLS1.3 implementation in Rust
================================

## Key generation
```
/bin/mkdir temp
openssl req -x509 -nodes -days 36500 -newkey ec:<(openssl ecparam -name prime256v1) -keyout temp/key.pem -out temp/cert.pem
```

## Debug server

```
openssl s_server -accept 50000 -cert temp/cert.pem -key temp/key.pem -CAfile cert.pem -cipher AES128-GCM-SHA256 -serverpref -state -debug -status_verbose
```