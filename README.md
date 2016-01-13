# rust-http-async
A (very simple) HTTPS "hello world" server. Uses a [forked](https://github.com/youngspe/gj) version of [GJ](https://github.com/dwrensha/gj) and [rust-openssl](https://github.com/sfackler/rust-openssl).

## Usage
`cargo run`

Create a cert and key at `./new.cert.crt` and `./new.cert.key`, respectively.

Send a request to `https://127.0.0.1:1337` and see what happens.
