from libcpp cimport bool

cdef extern from "<stdint.h>":
    ctypedef   signed char  int8_t
    ctypedef   signed short int16_t
    ctypedef   signed int   int32_t
    ctypedef   signed long  int64_t
    ctypedef unsigned char  uint8_t
    ctypedef unsigned short uint16_t
    ctypedef unsigned int   uint32_t
    ctypedef unsigned long long uint64_t

cdef extern from "netinet/in.h":
    struct in_addr:
        uint32_t s_addr
    struct sockaddr_in:
        unsigned short int sin_family
        uint16_t sin_port
        in_addr sin_addr
    
    ctypedef	uint32_t    in_addr_t
    # in_addr_t inet_addr(const char *cp)

cdef extern from "net/if.h":
    cdef enum:
        IFNAMSIZ

cdef extern from "c_lib/wireguard.h":
    struct timespec64:
        int64_t tv_sec
        int64_t tv_nsec

    ctypedef uint8_t wg_key[32]
    ctypedef char wg_key_b64_string[44]


    ctypedef struct wg_allowedip:
        uint16_t family
        in_addr ip4
        uint8_t cidr
        wg_allowedip *next_allowedip

    enum wg_peer_flags:
        WGPEER_REMOVE_ME = 1U << 0,
        WGPEER_REPLACE_ALLOWEDIPS = 1U << 1,
        WGPEER_HAS_PUBLIC_KEY = 1U << 2,
        WGPEER_HAS_PRESHARED_KEY = 1U << 3,
        WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL = 1U << 4

    ctypedef struct wg_peer:
        wg_peer_flags flags
        wg_key public_key
        wg_key preshared_key
        sockaddr_in endpoint
        timespec64 last_handshake_time
        uint64_t rx_bytes, tx_bytes
        uint16_t persistent_keepalive_interval
        wg_allowedip *first_allowedip
        wg_allowedip *last_allowedip
        wg_peer *next_peer

    enum wg_device_flags:
        WGDEVICE_REPLACE_PEERS = 1U << 0,
        WGDEVICE_HAS_PRIVATE_KEY = 1U << 1,
        WGDEVICE_HAS_PUBLIC_KEY = 1U << 2,
        WGDEVICE_HAS_LISTEN_PORT = 1U << 3,
        WGDEVICE_HAS_FWMARK = 1U << 4

    ctypedef struct wg_device:
        char name[IFNAMSIZ]
        uint32_t ifindex
        wg_device_flags flags
        wg_key public_key
        wg_key private_key
        uint32_t fwmark
        uint16_t listen_port
        wg_peer *first_peer
        wg_peer *last_peer

    char* wg_list_device_names()
    void wg_key_to_base64(wg_key_b64_string base64, const wg_key key)
    int wg_key_from_base64(wg_key key, const wg_key_b64_string base64)
    bool wg_key_is_zero(const wg_key key)
    void wg_generate_public_key(wg_key public_key, const wg_key private_key)
    void wg_generate_private_key(wg_key private_key)
    void wg_generate_preshared_key(wg_key preshared_key)
    int wg_add_device(const char *device_name)
    int wg_get_device(wg_device **dev, const char *device_name)
    int wg_del_device(const char *device_name)
    int wg_set_device(wg_device *dev)

cdef extern from "c_lib/c_fixes.c":
    char *wg_list_device_names_fixed()
