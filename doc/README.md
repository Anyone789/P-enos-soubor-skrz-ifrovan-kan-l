# README

Aplikace, která umožňuje přenést soubor skrz skrytý kanál, kde data jsou přenášena uvnitř ICMP/ICMPv6 Echo-Request/Response zpráv.
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
- Crypto: použij OpenSSL EVP API. Doporučeno AES-256-GCM + PBKDF2-HMAC-SHA256.
- Protokol: viz `doc/manual.pdf` pro přesnou binární specifikaci rámců.
