YKOATH-RS
===========

YKOATH-RS is a simple GTK indicator applet that lists any YubiKeys that are 
detected and allows you to view TOTP codes for 2 factor authentication and 
click to copy to clipboard.

> **Disclaimer:** I wrote this for myself, because the `yubioath-desktop` 
> application did not suit my needs and I'm also learning Rust. Merge 
> requests are very welcome, but this is a hobby project that I am pretty
> unlikely to consistently support and maintain.

```
cargo install ykoath
ykoath
```

There's also a small library exposed if you need it.

License
-------

LGPL-3.0
