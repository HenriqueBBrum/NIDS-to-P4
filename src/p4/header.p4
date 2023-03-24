#ifndef __HEADER_P4__
#define __HEADER_P4__ 1

// Ethernet
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ALERT = 0x2345;

// IPv4
const bit<8> TYPE_TCP = 0x06;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header generic_transport_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header tcp_options_t {
    bit<160> options;
}

struct metadata {
    bool redirect_to_ids;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    @name("transport")
    generic_transport_t transport;
    @name("tcp")
    tcp_t        tcp;
    @name("tcp_options")
    tcp_options_t tcp_options;
}

#endif // __HEADER_P4__
