/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TABLE_NUM = 1;

const bit<16> ETHER_HEADER_LENGTH = 14;
const bit<16> IPV4_HEADER_LENGTH = 20;
const bit<16> ICMP_HEADER_LENGTH = 8;
const bit<16> TCP_HEADER_LENGTH = 20;
const bit<16> UDP_HEADER_LENGTH = 8;

#define MAX_HOPS 29
#define IP_PROTOCOLS_ICMP 1
#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17
#define MAX_STRIDE 3
 
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<8>  patrn_state_t;
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<8> string_t;
typedef bit<16> state_t;
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

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> icmpHdrChecksum;
    bit<16> id;
    bit<16> seq;
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
    bit<16> length_;
    bit<16> checksum;
}

header patrn_t {
    bit<8> pattern;
}






struct metadata { 
    state_t state;
    bit<8> pattern_num;
    bit<16> payload_length;
    bit<16> non_payload_length;
    bit<8> flags;// 1 recir 2 drop 3 accept
    bit<8> one_pass_pattern_num;
    bit<8> stride;
    bit<1> non_first_pass;
    
    patrn_state_t pattern_state; //for multi-pattern logic
}

struct headers {
    @name("ethernet")
    ethernet_t              ethernet;
    @name("ipv4")
    ipv4_t                  ipv4;
    @name("icmp")
    icmp_t                  icmp;
    @name("tcp")
    tcp_t                   tcp;
    @name("udp")
    udp_t                   udp;
    patrn_t[MAX_HOPS]       patrns;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser ParserImpl(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet); 
        // meta.non_first_pass = 1;
        meta.non_payload_length = ETHER_HEADER_LENGTH;
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.non_payload_length = meta.non_payload_length + IPV4_HEADER_LENGTH;//34
        
        transition select(hdr.ipv4.protocol){
            IP_PROTOCOLS_ICMP: parse_icmp;
            IP_PROTOCOLS_TCP: parse_tcp;
            IP_PROTOCOLS_UDP: parse_udp;
            default: accept;
        }  
    }
    
    state parse_icmp {
        packet.extract(hdr.icmp);
        meta.non_payload_length = meta.non_payload_length + ICMP_HEADER_LENGTH;
        meta.pattern_num = 0;

        meta.payload_length = hdr.ipv4.totalLen + 14 - meta.non_payload_length;
        transition prepare_parse_pattern;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.non_payload_length = meta.non_payload_length + TCP_HEADER_LENGTH;
        meta.pattern_num = 0;
        meta.payload_length = hdr.ipv4.totalLen + 14 - meta.non_payload_length;
        transition prepare_parse_pattern;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.non_payload_length = meta.non_payload_length + UDP_HEADER_LENGTH;
        meta.pattern_num = 0;
        meta.payload_length = hdr.ipv4.totalLen + 14 - meta.non_payload_length;
        transition prepare_parse_pattern;
    }

    state prepare_parse_pattern {
        transition select(meta.payload_length) {
            0: accept;         
            default: parse_pattern;
        }
    }

    state parse_pattern{
        packet.extract(hdr.patrns.next);
        meta.pattern_num = meta.pattern_num + 1;
        meta.payload_length = meta.payload_length - 1;
        transition select(meta.payload_length) {
            0: accept;         
            default: parse_pattern;
        }
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control ingress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


//********** write the root state ID into metadate from table entries ***************  
    action a_get_root_state(state_t root_state){
        meta.state = root_state;
    }

    table t_get_root_state{
        key = {}
        actions ={
           a_get_root_state;
        }
    }
//***** k-stride DFA table ****************************************************
    action a_drop() {
        mark_to_drop(standard_metadata);
    }

    action a_nop() {}
   
    action a_set_state_1(state_t _state, patrn_state_t modifier){
        meta.state = _state;
        hdr.patrns.pop_front(1);
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 1;
        meta.pattern_num = meta.pattern_num - 1;
        meta.pattern_state = meta.pattern_state | modifier;
    }

    action a_set_state_2(state_t _state, patrn_state_t modifier){
        meta.state = _state;
        hdr.patrns.pop_front(2);
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 2;
        meta.pattern_num = meta.pattern_num - 2;
        meta.pattern_state = meta.pattern_state | modifier;

    }

    action a_set_state_3(state_t _state, patrn_state_t modifier){
        meta.state = _state;
        hdr.patrns.pop_front(3);  
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 3;
        meta.pattern_num = meta.pattern_num - 3;
        meta.pattern_state = meta.pattern_state | modifier;

    }
    
    action a_mark_as_to_recirculate(){
        meta.flags = 1;
        meta.non_first_pass = 1;
    }

    action a_mark_as_to_drop(){
        meta.flags = 2;
    }


    table t_DFA_match_0 {
        key = {
            hdr.patrns[0].pattern: ternary;
            hdr.patrns[1].pattern: ternary;

            // hdr.patrns[2].pattern: ternary;
            meta.state: ternary;
        }
        actions = {
            a_set_state_1;
            a_set_state_2;
            a_set_state_3;
            a_drop;
        }
        size = 1024;
    }
    table t_DFA_match_1 {
        key = {
            hdr.patrns[0].pattern: ternary;
            hdr.patrns[1].pattern: ternary;
            // hdr.patrns[2].pattern: ternary;

            // hdr.patrns[2].pattern: ternary;

            meta.state: ternary;
        }
        actions = {
            a_set_state_1;
            a_set_state_2;
            a_set_state_3;
            a_drop;
        }
        size = 1024;
    }
//***** Policy Table depending on meta.Pattern_state ***********************

    action a_set_lpm(){
        meta.flags = 3;
    }
    table t_policy {
        key = {
            meta.pattern_state: ternary;
        }   
        actions = {
            a_drop;
            a_set_lpm;
        }
        size = 1024;
    }

//***** ipv4_lpm table ****************************************************
    action a_ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table t_ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            a_ipv4_forward;
            a_drop;
        }
        size = 1024;
    }


//*****************************************************************************
    apply {
        if (hdr.patrns[0].isValid())
        { 
            
            if(meta.non_first_pass == 0)
            {
                t_get_root_state.apply();
            }
            
            t_DFA_match_0.apply();
            t_DFA_match_1.apply();
            if (meta.pattern_num > 0)
            {
                a_mark_as_to_recirculate();
            }
            else {
                t_policy.apply();
            }

        }
        if (meta.flags == 3)
        {
             t_ipv4_lpm.apply();
        }   
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control egress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {  
        if (hdr.ipv4.isValid())
        {
            if (meta.flags == 1 )
            {
                recirculate(meta);
            }       
        }     
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control computeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
    update_checksum(
        hdr.ipv4.isValid(),
        { 
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr 
        },
        hdr.ipv4.hdrChecksum,
        HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
