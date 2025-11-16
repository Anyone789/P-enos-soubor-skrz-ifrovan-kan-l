# secret — README (skeleton)

Build:
```
make
```

Run server (listening):
```
./secret -l
```

Run client (send file):
```
./secret -r ./file.bin -s 127.0.0.1
```

Notes:
- Tento skeleton neobsahuje plnou implementaci; slouží jako výchozí bod.
- Crypto: použij OpenSSL EVP API. Doporučeno AES-256-GCM + PBKDF2-HMAC-SHA256.
- Protokol: viz `doc/protocol.md` pro přesnou binární specifikaci rámců.
