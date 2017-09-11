# Paranoid

Paranoid is a [limited](#limitations) but fully rootless containeriztion tool. It allows unprivelged users on a system 
to create light-weight containers in which they can act as `root`.

It definitely should not be used for anything serious. That said, since it doesn't require any elevated privileges, the 
risk of escape is only as great as the user's rights outside of the container.

[![asciicast](https://asciinema.org/a/4RZtd6e1xKBS3MpUha9Qe2fF2.png)](https://asciinema.org/a/4RZtd6e1xKBS3MpUha9Qe2fF2)

## Usage

```
Usage: paranoid [OPTION...] --root=ROOT_PATH -- INIT [INIT_ARGS...]

  -e, --expose=PORT:PORT:PROTOCOL
                             Expose PORT inside container as PORT on host via
                             PROTOCOL (requires networking)
  -h, --hostname=HOSTNAME    Set the hostname within the container
  -N, --disable-networking   Disable networking within the container
  -r, --root=ROOT_PATH       Set the root within the container
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version
```

  1. Extract [a rootfs tarball](https://us.images.linuxcontainers.org/images) somewhere on your system (you can safely 
  ignore any permission errors related to `mknod` -- `/dev` will mounted as `tmpfs` and populated during initialization 
  anyway).
  2. Run `paranoid --root=./path-to-extracted-root-fs -- /bin/sh -c "/bin/login -f root"` to get an 
  interactive shell as root inside the container.
  3. Profit!

**NOTE:** If networking does not seem to be working, make sure that the `eth0` interface is up, has the address 
`10.0.15.2`, is configured with the netmask `255.255.255.252` (`10.0.15.0/30`), and has `10.0.15.1` as a default gateway. You will also need to specify a DNS server in `/etc/resolv.conf`.

## Limitations

  * If you want to support multiple users inside of your containers, make sure that the `newuidmap` and `newgidmap` 
    helpers from shadow are available on your system and that your user has entries in `/etc/subuid` and `/etc/subgid`. 
    On Ubuntu, shadow is configured to create entries for every user in `/etc/subuid` and `/etc/subgid` by default, but 
    the `newuidmap` and `newgidmap` helpers are in the `uidmap` package which is not installed by default anymore. 
    
    **TL;DR:** Run `sudo apt install uidmap` on Ubuntu and friends if you want to have more than the root user inside of 
    your containers.
  
  * Systemd won't work as init inside of paranoid containers
  
  * There is no way to expose a port from the container on the host *(coming soon)*
  
  * There is no way to expose a folder from the host inside of the container

## Todos

  * Figure out how to get Systemd working
  
  * Add port exposure / port forwarding to the networking stack *(in progress)*
  
  * Add folder exposure / bind mounts
  
  * Add proper DHCP and DNS servers to the networking stack instead of pre-configuring the adapter in the container 
  
  * Add sensible CLI interface and helpers for creating containers (extracting rootfs tars in usernamespace)

## Development

This project uses [cmake](https://cmake.org/cmake-tutorial/). You can probably get it building by running 
`cmake CMakeLists.txt` to generate the `Makefile`, then `make`.

An autotools-style configure script is also included for convenience.


## Contributing

Bug reports and pull requests are welcome on [GitHub](https://github.com/anarchocurious/paranoid).


## License

This library is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
