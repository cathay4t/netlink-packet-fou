# netlink-packet-fou

FOU (foo over UDP) generic netlink packet definitions for the
[rust-netlink](https://github.com/rust-netlink) project.

This crate only parses and emits the netlink payload of the `fou` generic
netlink family (`include/uapi/linux/fou.h` in the Linux kernel). To talk to
the kernel, use the `nl-fou` crate.

```rust,no_run
use netlink_packet_fou::{FouAttribute, FouCmd, FouMessage};

let message = FouMessage {
    cmd: FouCmd::Add,
    attributes: vec![
        FouAttribute::Port(5555),
        FouAttribute::Ipproto(17),
    ],
};
```

License: MIT
