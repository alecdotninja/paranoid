# Paranoid

Paranoid is a [limited](#limitations) but fully rootless containeriztion tool. It allows unprivelged users on a system 
to create light-weight containers in which they can act as `root`.

It definately shouldn't be used for anything serious. That said, since it doesn't require any elevated privileges, the 
risk of escape is only as great as the user's rights outside of the container.

## Usage

Paranoid only does  one thing, so there's only one command to learn. 

`paranoid` requires at least three arguments. The hostname of the new container, the path of the new rootfs, and the
path to the init process **relative to the new rootfs**. Any additional arguments will be passed on to PID 1.

![demo](demo.gif)

  1. Extract [a rootfs tarball](https://us.images.linuxcontainers.org/images) somewhere on your system (you can safely 
  ignore any permission errors related to `mknod` -- `/dev` will mounted as `tmpfs` and populated during initialization 
  anyway).
  2. Run `paranoid container-hostname ./path-to-extracted-root-fs /bin/sh -c "/bin/login -f root"` to get an 
  interactive shell as root inside the container.
  3. Profit!

**NOTE:** If networking does not seem to be working, make sure that the `eth0` interface is up, has the address 
`10.0.15.2`, is configured with the netmask `255.255.255.0` (`10.0.15.0/24`), and has `10.0.15.1` as a default gateway. You will also need to specify a DNS server in `/etc/resolv.conf`.

## Limitations

  * systemd hangs without output when used as the init system
  * There is no way to expose a port from the container
  * Networking does not support ICMP (ping/tracert)

## Todos

  * Figure out why systemd hangs without output
  * Add port exposure / port forwarding to the networking stack
  * Add an ICMP relay (taking advantage of setuid binaries on the host like `ping` and `tracert`)
  * Cleanup networking stack so that it can support proper local bindings and IP forwarding
  * Add proper DHCP and DNS servers to the networking stack instead of pre-configuring the adapter in the container 
  * Move the networking stack into it's own process so that it can be sandboxed and shared between multiple containers

## Development

This project uses [cmake](https://cmake.org/cmake-tutorial/). You can probably get it building by running 
`cmake CMakeLists.txt` to generate the `Makefile`, then `make`.


## Contributing

Bug reports and pull requests are welcome on [GitHub](https://github.com/anarchocurious/paranoid).


## License

This library is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
