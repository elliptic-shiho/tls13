TLS1.3 implementation in Rust
================================

## Key generation
```
/bin/mkdir temp
openssl req -x509 -nodes -days 36500 -newkey ec:<(openssl ecparam -name prime256v1) -keyout temp/key.pem -out temp/cert.pem
```

## Debug server

```
openssl s_server -accept 50000 -cert temp/cert.pem -key temp/key.pem -CAfile temp/cert.pem -cipher AES128-GCM-SHA256 -serverpref -state -debug -status_verbose -named_curve secp256r1 -sigalgs ecdsa_secp256r1_sha256 -trace -security_debug_verbose -msg -keylogfile /dev/stdout
```

## References
* [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
* [RFC 6066: Transport Layer Security (TLS) Extensions: Extension Definitions](https://datatracker.ietf.org/doc/html/rfc6066)
* [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://datatracker.ietf.org/doc/html/rfc5869)
* [RFC 5116: An Interface and Algorithms for Authenticated Encryption](https://datatracker.ietf.org/doc/html/rfc5116)
* [RFC 9001: Using TLS to Secure QUIC](https://datatracker.ietf.org/doc/html/rfc9001)
  - for test vector
* [draft-ietf-tls-tls13-vectors-06: Example Handshake Traces for TLS 1.3](https://datatracker.ietf.org/doc/html/draft-ietf-tls-tls13-vectors-06)
* Ivan Ristić. 2022. [Bulletproof TLS and PKI, Second Edition: Understanding and Deploying SSL/TLS and PKI to Secure Servers and Web Applications](https://www.feistyduck.com/books/bulletproof-tls-and-pki/). ISBN: 978-1-907117-09-1. Feisty Duck. 
  - 日本語訳: Ivan Ristić (著), 齋藤孝道 (監訳). 2023. [プロフェッショナルTLS&PKI 改題第2版](https://www.lambdanote.com/products/tls-pki-2). ISBN: 978-4-908686-19-1. ラムダノート. 

## License
MIT. 
