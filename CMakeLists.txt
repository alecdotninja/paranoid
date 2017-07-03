cmake_minimum_required(VERSION 3.5)
project(paranoid)

set(CMAKE_C_STANDARD 99)

include_directories(
        src/include
        vendor/lwip/src/include
        vendor/libcgroup/include
        vendor/libseccomp/include
        vendor/libcap/libcap/include
)

set(
        LWIP_CONIFG_FILES

        src/include/lwipopts.h
        src/include/arch/cc.h
        src/include/arch/perf.h
        src/lwip/arch.c
)

set(
        LWIP_SOURCE_FILES

        ${LWIP_CONIFG_FILES}

        vendor/lwip/src/api/api_lib.c
        vendor/lwip/src/api/api_msg.c
        vendor/lwip/src/api/err.c
        vendor/lwip/src/api/if_api.c
        vendor/lwip/src/api/netbuf.c
        vendor/lwip/src/api/netdb.c
        vendor/lwip/src/api/netifapi.c
        vendor/lwip/src/api/sockets.c
        vendor/lwip/src/api/tcpip.c
        vendor/lwip/src/core/altcp.c
        vendor/lwip/src/core/altcp_tcp.c
        vendor/lwip/src/core/def.c
        vendor/lwip/src/core/dns.c
        vendor/lwip/src/core/inet_chksum.c
        vendor/lwip/src/core/init.c
        vendor/lwip/src/core/ip.c
        vendor/lwip/src/core/ipv4/autoip.c
        vendor/lwip/src/core/ipv4/dhcp.c
        vendor/lwip/src/core/ipv4/etharp.c
        vendor/lwip/src/core/ipv4/icmp.c
        vendor/lwip/src/core/ipv4/igmp.c
        vendor/lwip/src/core/ipv4/ip4_addr.c
        vendor/lwip/src/core/ipv4/ip4.c
        vendor/lwip/src/core/ipv4/ip4_frag.c
        vendor/lwip/src/core/mem.c
        vendor/lwip/src/core/memp.c
        vendor/lwip/src/core/netif.c
        vendor/lwip/src/core/pbuf.c
        vendor/lwip/src/core/raw.c
        vendor/lwip/src/core/stats.c
        vendor/lwip/src/core/sys.c
        vendor/lwip/src/core/tcp.c
        vendor/lwip/src/core/tcp_in.c
        vendor/lwip/src/core/tcp_out.c
        vendor/lwip/src/core/timeouts.c
        vendor/lwip/src/core/udp.c
        vendor/lwip/src/include/lwip/altcp.h
        vendor/lwip/src/include/lwip/altcp_tcp.h
        vendor/lwip/src/include/lwip/altcp_tls.h
        vendor/lwip/src/include/lwip/api.h
        vendor/lwip/src/include/lwip/arch.h
        vendor/lwip/src/include/lwip/autoip.h
        vendor/lwip/src/include/lwip/debug.h
        vendor/lwip/src/include/lwip/def.h
        vendor/lwip/src/include/lwip/dhcp6.h
        vendor/lwip/src/include/lwip/dhcp.h
        vendor/lwip/src/include/lwip/dns.h
        vendor/lwip/src/include/lwip/err.h
        vendor/lwip/src/include/lwip/errno.h
        vendor/lwip/src/include/lwip/etharp.h
        vendor/lwip/src/include/lwip/ethip6.h
        vendor/lwip/src/include/lwip/icmp6.h
        vendor/lwip/src/include/lwip/icmp.h
        vendor/lwip/src/include/lwip/if_api.h
        vendor/lwip/src/include/lwip/igmp.h
        vendor/lwip/src/include/lwip/inet_chksum.h
        vendor/lwip/src/include/lwip/inet.h
        vendor/lwip/src/include/lwip/init.h
        vendor/lwip/src/include/lwip/ip4_addr.h
        vendor/lwip/src/include/lwip/ip4_frag.h
        vendor/lwip/src/include/lwip/ip4.h
        vendor/lwip/src/include/lwip/ip6_addr.h
        vendor/lwip/src/include/lwip/ip6_frag.h
        vendor/lwip/src/include/lwip/ip6.h
        vendor/lwip/src/include/lwip/ip6_zone.h
        vendor/lwip/src/include/lwip/ip_addr.h
        vendor/lwip/src/include/lwip/ip.h
        vendor/lwip/src/include/lwip/mem.h
        vendor/lwip/src/include/lwip/memp.h
        vendor/lwip/src/include/lwip/mld6.h
        vendor/lwip/src/include/lwip/nd6.h
        vendor/lwip/src/include/lwip/netbuf.h
        vendor/lwip/src/include/lwip/netdb.h
        vendor/lwip/src/include/lwip/netifapi.h
        vendor/lwip/src/include/lwip/netif.h
        vendor/lwip/src/include/lwip/opt.h
        vendor/lwip/src/include/lwip/pbuf.h
        vendor/lwip/src/include/lwip/priv/altcp_priv.h
        vendor/lwip/src/include/lwip/priv/api_msg.h
        vendor/lwip/src/include/lwip/priv/memp_priv.h
        vendor/lwip/src/include/lwip/priv/memp_std.h
        vendor/lwip/src/include/lwip/priv/nd6_priv.h
        vendor/lwip/src/include/lwip/priv/sockets_priv.h
        vendor/lwip/src/include/lwip/priv/tcpip_priv.h
        vendor/lwip/src/include/lwip/priv/tcp_priv.h
        vendor/lwip/src/include/lwip/prot/autoip.h
        vendor/lwip/src/include/lwip/prot/dhcp.h
        vendor/lwip/src/include/lwip/prot/dns.h
        vendor/lwip/src/include/lwip/prot/etharp.h
        vendor/lwip/src/include/lwip/prot/ethernet.h
        vendor/lwip/src/include/lwip/prot/icmp6.h
        vendor/lwip/src/include/lwip/prot/icmp.h
        vendor/lwip/src/include/lwip/prot/igmp.h
        vendor/lwip/src/include/lwip/prot/ip4.h
        vendor/lwip/src/include/lwip/prot/ip6.h
        vendor/lwip/src/include/lwip/prot/ip.h
        vendor/lwip/src/include/lwip/prot/mld6.h
        vendor/lwip/src/include/lwip/prot/nd6.h
        vendor/lwip/src/include/lwip/prot/tcp.h
        vendor/lwip/src/include/lwip/prot/udp.h
        vendor/lwip/src/include/lwip/raw.h
        vendor/lwip/src/include/lwip/sio.h
        vendor/lwip/src/include/lwip/snmp.h
        vendor/lwip/src/include/lwip/sockets.h
        vendor/lwip/src/include/lwip/stats.h
        vendor/lwip/src/include/lwip/sys.h
        vendor/lwip/src/include/lwip/tcpbase.h
        vendor/lwip/src/include/lwip/tcp.h
        vendor/lwip/src/include/lwip/tcpip.h
        vendor/lwip/src/include/lwip/timeouts.h
        vendor/lwip/src/include/lwip/udp.h
        vendor/lwip/src/include/netif/bridgeif.h
        vendor/lwip/src/include/netif/bridgeif_opts.h
        vendor/lwip/src/include/netif/etharp.h
        vendor/lwip/src/include/netif/ethernet.h
        vendor/lwip/src/include/netif/lowpan6.h
        vendor/lwip/src/include/netif/lowpan6_opts.h
        vendor/lwip/src/include/netif/ppp/ccp.h
        vendor/lwip/src/include/netif/ppp/chap-md5.h
        vendor/lwip/src/include/netif/ppp/chap_ms.h
        vendor/lwip/src/include/netif/ppp/chap-new.h
        vendor/lwip/src/include/netif/ppp/eap.h
        vendor/lwip/src/include/netif/ppp/ecp.h
        vendor/lwip/src/include/netif/ppp/eui64.h
        vendor/lwip/src/include/netif/ppp/fsm.h
        vendor/lwip/src/include/netif/ppp/ipcp.h
        vendor/lwip/src/include/netif/ppp/lcp.h
        vendor/lwip/src/include/netif/ppp/magic.h
        vendor/lwip/src/include/netif/ppp/mppe.h
        vendor/lwip/src/include/netif/ppp/polarssl/arc4.h
        vendor/lwip/src/include/netif/ppp/polarssl/des.h
        vendor/lwip/src/include/netif/ppp/polarssl/md4.h
        vendor/lwip/src/include/netif/ppp/polarssl/md5.h
        vendor/lwip/src/include/netif/ppp/polarssl/sha1.h
        vendor/lwip/src/include/netif/ppp/pppapi.h
        vendor/lwip/src/include/netif/ppp/pppcrypt.h
        vendor/lwip/src/include/netif/ppp/pppdebug.h
        vendor/lwip/src/include/netif/ppp/ppp.h
        vendor/lwip/src/include/netif/ppp/ppp_impl.h
        vendor/lwip/src/include/netif/ppp/pppoe.h
        vendor/lwip/src/include/netif/ppp/pppol2tp.h
        vendor/lwip/src/include/netif/ppp/ppp_opts.h
        vendor/lwip/src/include/netif/ppp/pppos.h
        vendor/lwip/src/include/netif/ppp/upap.h
        vendor/lwip/src/include/netif/ppp/vj.h
        vendor/lwip/src/include/posix/arpa/inet.h
        vendor/lwip/src/include/posix/errno.h
        vendor/lwip/src/include/posix/netdb.h
        vendor/lwip/src/include/posix/net/if.h
        vendor/lwip/src/include/posix/sys/socket.h
        vendor/lwip/src/netif/bridgeif.c
        vendor/lwip/src/netif/ethernet.c
        vendor/lwip/src/netif/ethernetif.c
        vendor/lwip/src/netif/lowpan6.c
        vendor/lwip/src/netif/ppp/auth.c
        vendor/lwip/src/netif/ppp/ccp.c
        vendor/lwip/src/netif/ppp/chap-md5.c
        vendor/lwip/src/netif/ppp/chap_ms.c
        vendor/lwip/src/netif/ppp/chap-new.c
        vendor/lwip/src/netif/ppp/demand.c
        vendor/lwip/src/netif/ppp/eap.c
        vendor/lwip/src/netif/ppp/ecp.c
        vendor/lwip/src/netif/ppp/eui64.c
        vendor/lwip/src/netif/ppp/fsm.c
        vendor/lwip/src/netif/ppp/ipcp.c
        vendor/lwip/src/netif/ppp/lcp.c
        vendor/lwip/src/netif/ppp/magic.c
        vendor/lwip/src/netif/ppp/mppe.c
        vendor/lwip/src/netif/ppp/multilink.c
        vendor/lwip/src/netif/ppp/polarssl/arc4.c
        vendor/lwip/src/netif/ppp/polarssl/des.c
        vendor/lwip/src/netif/ppp/polarssl/md4.c
        vendor/lwip/src/netif/ppp/polarssl/md5.c
        vendor/lwip/src/netif/ppp/polarssl/sha1.c
        vendor/lwip/src/netif/ppp/pppapi.c
        vendor/lwip/src/netif/ppp/ppp.c
        vendor/lwip/src/netif/ppp/pppcrypt.c
        vendor/lwip/src/netif/ppp/pppoe.c
        vendor/lwip/src/netif/ppp/pppol2tp.c
        vendor/lwip/src/netif/ppp/pppos.c
        vendor/lwip/src/netif/ppp/upap.c
        vendor/lwip/src/netif/ppp/utils.c
        vendor/lwip/src/netif/ppp/vj.c
)

set(
        CONTAINER_SOURCE_FILES

        src/include/container/container.h
        src/container/container.c

        src/include/container/fs.h
        src/container/fs.c

        src/include/container/init.h
        src/container/init.c

        src/include/container/networking.h
        src/container/networking.c

        src/include/container/plumbing.h
        src/container/plumbing.c

        src/include/container/signaling.h
        src/container/signaling.c

        src/include/container/spawn.h
        src/container/spawn.c

        src/include/container/tty.h
        src/container/tty.c

        src/include/container/unsafe.h
        src/container/unsafe.c

        src/include/container/userns.h
        src/container/userns.c
        src/lwip/tunif.c)

add_executable(paranoid ${LWIP_SOURCE_FILES} ${CONTAINER_SOURCE_FILES} src/paraniod.c)
target_link_libraries(paranoid pthread)

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libcgroup.a
        COMMAND autoreconf -fi
        COMMAND ./configure --enable-static
        COMMAND cp src/.libs/libcgroup.a ${CMAKE_CURRENT_BINARY_DIR}/libcgroup.a
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/vendor/libcgroup
)

add_custom_target(libcgroup DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/libcgroup.a)
add_dependencies(paranoid libcgroup)
target_link_libraries(paranoid ${CMAKE_CURRENT_BINARY_DIR}/libcgroup.a)

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libseccomp.a
        COMMAND autoreconf -fi
        COMMAND ./configure --enable-static
        COMMAND make
        COMMAND cp src/.libs/libseccomp.a ${CMAKE_CURRENT_BINARY_DIR}/libseccomp.a
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/vendor/libseccomp
)

add_custom_target(libseccomp DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/libseccomp.a)
add_dependencies(paranoid libseccomp)
target_link_libraries(paranoid ${CMAKE_CURRENT_BINARY_DIR}/libseccomp.a)

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libcap.a
        COMMAND make
        COMMAND cp libcap/libcap.a ${CMAKE_CURRENT_BINARY_DIR}/libcap.a
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/vendor/libcap
)

add_custom_target(libcap DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/libcap.a)
add_dependencies(paranoid libcap)
target_link_libraries(paranoid ${CMAKE_CURRENT_BINARY_DIR}/libcap.a)
