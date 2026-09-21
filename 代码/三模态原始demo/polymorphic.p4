/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_SRCROUTING    = 0x1234;

const bit<16> TYPE_IPV4          = 0x800;
const bit<16> TYPE_ARP           = 0x0806;

const bit<16> TYPE_IPV6          = 0x86DD;

const bit<16> POLY_MAGIC         = 0x504f; // ASCII "PO"
const bit<8>  POLY_IP_PROTOCOL   = 253;
const bit<16> POLY_UDP_PORT      = 5000;
const bit<16> POLY_MCAST_GROUP   = 10;

const bit<8>  MODE_IPV4 = 1;
const bit<8>  MODE_IPV6 = 2;
const bit<8>  MODE_SR   = 3;

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

#define MAX_HOPS 9

/*
 * STUDENT TODO ROADMAP
 *
 * This starter intentionally remains the verified three-path baseline. It
 * compiles before any experiment code is added. Complete the extension in
 * stages and keep every stage compilable:
 *
 *   M1: define PolyShim, protected_data and saved inner-IPv4 headers;
 *   M2: parse UDP dport 5000 with exactly 16 protected bytes;
 *   M3: add sequence/CRC metadata and an ingress scheduling table;
 *   M4: set mcast_grp and build IPv4/IPv6/SR outer headers in MyEgress;
 *   M5: add destination-gateway register state and 2-out-of-3 adjudication;
 *   M6: restore the original IPv4 packet and emit it at host-facing port 1.
 *
 * The field contract and pseudocode are in STUDENT_TODO.md. Do not paste a
 * complete solution here first: implement and validate one milestone at a
 * time so a failing stage can be located from pcap and counter evidence.
 */

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header srcRoute_t {
    bit<1>    bos;
    bit<15>   port;
}

header arp_t {
    bit<16> htype; // format of hardware address
    bit<16> ptype; // format of protocol address
    bit<8>  hlen; // length of hardware address
    bit<8>  plen; // length of protocol address
    bit<16> oper; // request or reply operation
    macAddr_t sha; //src mac address
    ip4Addr_t spa; //src ip address
    macAddr_t tha; // dst mac address
    ip4Addr_t tpa; // dst ip address
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

header ipv6_t{
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel;
    bit<16>   payLoadLen;
    bit<8>    nextHdr;
    bit<8>    hopLimit;
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> pkt_length;
    bit<16> checksum;
}

header polyShim_t {
    bit<16> magic;
    bit<8>  direction;
    bit<32> sequence_number;
    bit<8>  modality_id;
    bit<32> source_crc32;
    bit<16> inner_ether_type;
}

header protectedData_t {
    bit<128> value;
}

struct metadata {
    ip4Addr_t   dst_ipv4; // dst ip

    bit<32>     sequence_number;
    bit<32>     source_crc32;
    bit<8>      direction;

    // M5 裁决临时字段
    bit<32>     adj_slot;
    bit<32>     observed_crc;
    bit<1>      output_now;
    bit<1>      adj_done;
}

struct headers {
    ethernet_t  ethernet;
    srcRoute_t[MAX_HOPS]    srcRoutes;
    arp_t       arp;
    ipv4_t      ipv4;
    ipv6_t      ipv6;
    polyShim_t  polyShim;
    ipv4_t      inner_ipv4;
    tcp_t       tcp;
    udp_t       udp;
    protectedData_t protected_data;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_SRCROUTING: parse_srcRouting;
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP : parse_arp;
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }
    
    state parse_srcRouting {
        packet.extract(hdr.srcRoutes.next);
        transition select(hdr.srcRoutes.last.bos) {
            1: parse_after_sr;
            default: parse_srcRouting;
        }
    }

    state parse_after_sr {
        transition select(packet.lookahead<bit<16>>()) {
            POLY_MAGIC: parse_polyShim;
            default: parse_ipv4;
        }
    }
    
    state parse_arp {
        packet.extract(hdr.arp);
        meta.dst_ipv4 = hdr.arp.tpa;  //save dst ip
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            POLY_IP_PROTOCOL: parse_polyShim;
            default: accept;
        }
    }
    
    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            POLY_IP_PROTOCOL: parse_polyShim;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            POLY_UDP_PORT: parse_protected;
            default: accept;
        }
    }

    state parse_polyShim {
        packet.extract(hdr.polyShim);
        transition parse_inner_ipv4;
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            17: parse_inner_udp;
            default: accept;
        }
    }

    state parse_inner_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            POLY_UDP_PORT: parse_protected;
            default: accept;
        }
    }

    state parse_protected {
        packet.extract(hdr.protected_data);
        transition accept;
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // M5 裁决状态窗口
    register<bit<32>>(1024) seq_tag_reg;
    register<bit<32>>(1024) crc_cand1_reg;
    register<bit<32>>(1024) crc_cand2_reg;
    register<bit<8>>(1024)  mode_cand1_reg;
    register<bit<8>>(1024)  mode_cand2_reg;
    register<bit<8>>(1024)  seen_modes_reg;
    register<bit<2>>(1024)  cand_count_reg;
    register<bit<1>>(1024)  decided_reg;
    register<bit<32>>(1024) decided_crc_reg;

    counter(4, CounterType.packets) mode_good;
    counter(4, CounterType.packets) mode_bad;
    counter(1, CounterType.packets) no_majority_cnt;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action srcRoute_nhop() {
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;
        hdr.srcRoutes.pop_front(1);
    }

    action srcRoute_finish() {
        hdr.ethernet.etherType = TYPE_IPV4;
    }

    action update_ttl(){
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
	
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl         = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    action ipv6_forward(macAddr_t dstAddr,egressSpec_t port){
	standard_metadata.egress_spec = port;
	hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
	hdr.ethernet.dstAddr = dstAddr;
	hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }
    
    table ipv6_lpm{
    	key = {
	    hdr.ipv6.dstAddr: lpm;
	}
	actions = {
	    ipv6_forward;
	    drop;
	    NoAction;
	}		
	size = 1024;	
	default_action = drop();
    }

    action start_polymorphic(bit<8> packet_direction) {
        hdr.inner_ipv4 = hdr.ipv4;
        hdr.ipv4.setInvalid();

        meta.sequence_number = (bit<32>)standard_metadata.ingress_global_timestamp;
        meta.direction = packet_direction;

        meta.source_crc32 =
            hdr.inner_ipv4.srcAddr ^
            hdr.inner_ipv4.dstAddr ^
            ((bit<32>)hdr.inner_ipv4.protocol << 16) ^
            ((bit<32>)hdr.udp.srcPort) ^
            (((bit<32>)hdr.udp.dstPort) << 16) ^
            hdr.protected_data.value[127:96] ^
            hdr.protected_data.value[95:64] ^
            hdr.protected_data.value[63:32] ^
            hdr.protected_data.value[31:0];

        hdr.polyShim.setValid();
        hdr.polyShim.magic            = POLY_MAGIC;
        hdr.polyShim.direction        = packet_direction;
        hdr.polyShim.sequence_number  = meta.sequence_number;
        hdr.polyShim.modality_id      = 0;
        hdr.polyShim.source_crc32     = meta.source_crc32;
        hdr.polyShim.inner_ether_type = TYPE_IPV4;

        standard_metadata.mcast_grp = POLY_MCAST_GROUP;
    }

    action do_adjudicate() {
        meta.adj_done = 1;
        meta.adj_slot = hdr.polyShim.sequence_number & 1023;

        bit<32> cur_seq_tag;
        bit<32> cur_cand1;
        bit<32> cur_cand2;
        bit<8>  cur_mode1;
        bit<8>  cur_mode2;
        bit<8>  cur_seen;
        bit<2>  cur_count;
        bit<1>  cur_decided;
        bit<32> cur_winner;

        seq_tag_reg.read(cur_seq_tag, meta.adj_slot);
        crc_cand1_reg.read(cur_cand1, meta.adj_slot);
        crc_cand2_reg.read(cur_cand2, meta.adj_slot);
        mode_cand1_reg.read(cur_mode1, meta.adj_slot);
        mode_cand2_reg.read(cur_mode2, meta.adj_slot);
        seen_modes_reg.read(cur_seen, meta.adj_slot);
        cand_count_reg.read(cur_count, meta.adj_slot);
        decided_reg.read(cur_decided, meta.adj_slot);
        decided_crc_reg.read(cur_winner, meta.adj_slot);

        if (cur_seq_tag != hdr.polyShim.sequence_number) {
            cur_seq_tag  = hdr.polyShim.sequence_number;
            cur_cand1    = 0;
            cur_cand2    = 0;
            cur_mode1    = 0;
            cur_mode2    = 0;
            cur_seen     = 0;
            cur_count    = 0;
            cur_decided  = 0;
            cur_winner   = 0;
        }

        meta.observed_crc =
            hdr.inner_ipv4.srcAddr ^
            hdr.inner_ipv4.dstAddr ^
            ((bit<32>)hdr.inner_ipv4.protocol << 16) ^
            ((bit<32>)hdr.udp.srcPort) ^
            (((bit<32>)hdr.udp.dstPort) << 16) ^
            hdr.protected_data.value[127:96] ^
            hdr.protected_data.value[95:64] ^
            hdr.protected_data.value[63:32] ^
            hdr.protected_data.value[31:0];

        bit<8>  mode     = hdr.polyShim.modality_id;
        bit<8>  seen_bit = (bit<8>)1 << (mode - 1);

        if ((cur_seen & seen_bit) != 0) {
            meta.output_now = 0;
        } else {
            cur_seen = cur_seen | seen_bit;

            if (cur_decided == 1) {
                if (cur_winner != 0 && meta.observed_crc == cur_winner) {
                    mode_good.count((bit<32>)mode);
                } else {
                    mode_bad.count((bit<32>)mode);
                }
                meta.output_now = 0;
            }
            else if (cur_count == 0) {
                cur_cand1 = meta.observed_crc;
                cur_mode1 = mode;
                cur_count = 1;
                meta.output_now = 0;
            }
            else if (cur_count == 1) {
                if (meta.observed_crc == cur_cand1) {
                    cur_decided = 1;
                    cur_winner  = cur_cand1;
                    mode_good.count((bit<32>)cur_mode1);
                    mode_good.count((bit<32>)mode);
                    meta.output_now = 1;
                } else {
                    cur_cand2 = meta.observed_crc;
                    cur_mode2 = mode;
                    cur_count = 2;
                    meta.output_now = 0;
                }
            }
            else {
                cur_decided = 1;
                if (meta.observed_crc == cur_cand1) {
                    cur_winner = cur_cand1;
                    mode_good.count((bit<32>)cur_mode1);
                    mode_bad.count((bit<32>)cur_mode2);
                    mode_good.count((bit<32>)mode);
                    meta.output_now = 1;
                }
                else if (meta.observed_crc == cur_cand2) {
                    cur_winner = cur_cand2;
                    mode_bad.count((bit<32>)cur_mode1);
                    mode_good.count((bit<32>)cur_mode2);
                    mode_good.count((bit<32>)mode);
                    meta.output_now = 1;
                }
                else {
                    cur_winner = 0;
                    no_majority_cnt.count((bit<32>)0);
                    meta.output_now = 0;
                }
            }

            seq_tag_reg.write(meta.adj_slot, cur_seq_tag);
            crc_cand1_reg.write(meta.adj_slot, cur_cand1);
            crc_cand2_reg.write(meta.adj_slot, cur_cand2);
            mode_cand1_reg.write(meta.adj_slot, cur_mode1);
            mode_cand2_reg.write(meta.adj_slot, cur_mode2);
            seen_modes_reg.write(meta.adj_slot, cur_seen);
            cand_count_reg.write(meta.adj_slot, cur_count);
            decided_reg.write(meta.adj_slot, cur_decided);
            decided_crc_reg.write(meta.adj_slot, cur_winner);
        }
    }

    action restore_and_forward() {
        // 用保存的 inner_ipv4 替换外层
        hdr.ipv4              = hdr.inner_ipv4;
        hdr.ipv4.version      = 4;
        hdr.ipv4.ihl          = 5;
        hdr.ipv4.totalLen     = 44;
        hdr.ipv4.protocol     = 17;
        hdr.ipv4.ttl          = 64;
        hdr.ipv4.hdrChecksum  = 0;
        hdr.ipv4.setValid();

        hdr.inner_ipv4.setInvalid();
        hdr.ipv6.setInvalid();
        hdr.polyShim.setInvalid();

        hdr.srcRoutes[0].setInvalid();
        hdr.srcRoutes[1].setInvalid();
        hdr.srcRoutes[2].setInvalid();
        hdr.srcRoutes[3].setInvalid();
        hdr.srcRoutes[4].setInvalid();
        hdr.srcRoutes[5].setInvalid();
        hdr.srcRoutes[6].setInvalid();
        hdr.srcRoutes[7].setInvalid();
        hdr.srcRoutes[8].setInvalid();

        hdr.ethernet.etherType = TYPE_IPV4;

        if (meta.direction == 0) {
            hdr.ethernet.dstAddr = 0x080000000202;
            hdr.ethernet.srcAddr = 0x080000000200;
        } else {
            hdr.ethernet.dstAddr = 0x080000000101;
            hdr.ethernet.srcAddr = 0x080000000100;
        }

        standard_metadata.egress_spec = 1;
    }

    table gateway_role {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            do_adjudicate;
            NoAction;
        }
        size = 8;
        default_action = NoAction();
    }

    table polymorphic_schedule {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.ipv4.dstAddr              : exact;
            hdr.udp.dstPort               : exact;
        }
        actions = {
            start_polymorphic;
            NoAction;
        }
        size = 16;
        default_action = NoAction();
    }

    action send_arp_reply(macAddr_t macAddr) {
        hdr.ethernet.dstAddr = hdr.arp.sha;      // Ethernet target address = ARP source MAC address
        hdr.ethernet.srcAddr = macAddr; 	  // Ethernet source address = the action argument macAddr

        hdr.arp.oper         = ARP_OPER_REPLY;   // modify the ARP packet type to reply
        // set the fields to reply
        hdr.arp.tha          = hdr.arp.sha;      // ARP target MAC address = ARP source MAC address
        hdr.arp.tpa          = hdr.arp.spa;      // ARP target IP address = ARP source IP address
        hdr.arp.sha          = macAddr;          // ARP source MAC address = the action argument macAddr
        hdr.arp.spa          = meta.dst_ipv4;           // ARP source IP address = ARP target IP address

        standard_metadata.egress_spec = standard_metadata.ingress_port; // return to the port it comes from
    }

    table arp_match {
        key = {
            hdr.arp.oper           : exact;
            hdr.arp.tpa            : lpm;
        }
        actions = {
            send_arp_reply;
            drop;
        }
        const default_action = drop();
    }

    apply {
        if (hdr.ethernet.etherType == TYPE_IPV4
            && hdr.ipv4.isValid()
            && hdr.ipv4.protocol == 17
            && hdr.udp.isValid()
            && hdr.udp.dstPort == POLY_UDP_PORT
            && !hdr.polyShim.isValid()) {
            polymorphic_schedule.apply();
        }

        if (hdr.polyShim.isValid()
            && standard_metadata.ingress_port >= 2
            && standard_metadata.ingress_port <= 4) {
            meta.adj_done = 0;
            gateway_role.apply();
            if (meta.adj_done == 1) {
                if (meta.output_now == 1) {
                    restore_and_forward();
                } else {
                    mark_to_drop(standard_metadata);
                }
            }
        }

        if (meta.adj_done == 1) {
            // 已由目的网关处理完毕
        }
        else if (standard_metadata.mcast_grp == POLY_MCAST_GROUP) {
            // 已触发 multicast，交给 PRE 复制
        }
        else if (hdr.srcRoutes[0].isValid()){
            if (hdr.srcRoutes[0].bos == 1){
                srcRoute_finish();
            }
            srcRoute_nhop();
            if (hdr.ipv4.isValid()){
                update_ttl();
            }
        }
        else if(hdr.ethernet.etherType == TYPE_IPV4) {
            ipv4_lpm.apply();
        }
        else if(hdr.ethernet.etherType == TYPE_ARP) {
            arp_match.apply();
        }
        else if(hdr.ethernet.etherType == TYPE_IPV6){
	    ipv6_lpm.apply();
	}
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.polyShim.isValid()
            && standard_metadata.mcast_grp == POLY_MCAST_GROUP) {
            if (standard_metadata.egress_port == 2) {
                hdr.ipv4.setValid();
                hdr.ipv4.version        = 4;
                hdr.ipv4.ihl            = 5;
                hdr.ipv4.diffserv       = 0;
                hdr.ipv4.totalLen       = 78;
                hdr.ipv4.identification = 0;
                hdr.ipv4.flags          = 0;
                hdr.ipv4.fragOffset     = 0;
                hdr.ipv4.ttl            = 64;
                hdr.ipv4.protocol       = POLY_IP_PROTOCOL;
                hdr.ipv4.hdrChecksum    = 0;
                hdr.ipv4.srcAddr        = hdr.inner_ipv4.srcAddr;
                hdr.ipv4.dstAddr        = hdr.inner_ipv4.dstAddr;
                hdr.ethernet.etherType  = TYPE_IPV4;
                hdr.polyShim.modality_id = MODE_IPV4;
            }
            else if (standard_metadata.egress_port == 3) {
                hdr.ipv6.setValid();
                hdr.ipv6.version      = 6;
                hdr.ipv6.trafficClass = 0;
                hdr.ipv6.flowLabel    = 0;
                hdr.ipv6.payLoadLen   = 58;
                hdr.ipv6.nextHdr      = POLY_IP_PROTOCOL;
                hdr.ipv6.hopLimit     = 64;
                if (hdr.polyShim.direction == 0) {
                    hdr.ipv6.srcAddr = 0xfe800000000000000000000000001234;
                    hdr.ipv6.dstAddr = 0xfe800000000000000000000000005678;
                } else {
                    hdr.ipv6.srcAddr = 0xfe800000000000000000000000005678;
                    hdr.ipv6.dstAddr = 0xfe800000000000000000000000001234;
                }
                hdr.ethernet.etherType   = TYPE_IPV6;
                hdr.polyShim.modality_id = MODE_IPV6;
            }
            else if (standard_metadata.egress_port == 4) {
                if (hdr.polyShim.direction == 0) {
                    hdr.srcRoutes[0].setValid();
                    hdr.srcRoutes[0].bos  = 0;
                    hdr.srcRoutes[0].port = 2;
                    hdr.srcRoutes[1].setValid();
                    hdr.srcRoutes[1].bos  = 0;
                    hdr.srcRoutes[1].port = 2;
                    hdr.srcRoutes[2].setValid();
                    hdr.srcRoutes[2].bos  = 1;
                    hdr.srcRoutes[2].port = 1;
                } else {
                    hdr.srcRoutes[0].setValid();
                    hdr.srcRoutes[0].bos  = 0;
                    hdr.srcRoutes[0].port = 1;
                    hdr.srcRoutes[1].setValid();
                    hdr.srcRoutes[1].bos  = 0;
                    hdr.srcRoutes[1].port = 1;
                    hdr.srcRoutes[2].setValid();
                    hdr.srcRoutes[2].bos  = 1;
                    hdr.srcRoutes[2].port = 1;
                }
                hdr.ethernet.etherType   = TYPE_SRCROUTING;
                hdr.polyShim.modality_id = MODE_SR;
            }
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // TODO M1/M4/M6: emit newly introduced outer/PolyShim/inner headers in
        // wire order. Header validity decides which modality is serialized.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.polyShim);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.protected_data);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
