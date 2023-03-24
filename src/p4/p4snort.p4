#include <core.p4>
#include <v1model.p4>

#include "header.p4"
#include "parser_generic.p4"

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }

    action _drop() {
        mark_to_drop(standard_metadata);
    }

    table send_frame {
        actions = {
            rewrite_mac;
            _drop;
            NoAction;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
        default_action = NoAction();
    }
    apply {
        send_frame.apply();
    }
}


control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    bit<48> ONE_SECOND = 1000000;
    bit<48> last_timestamp = 0;
    register<bit<48>>(1) timeout_aux;

    counter(64, CounterType.packets) received;
    counter(64, CounterType.packets) redirected;
    counter(64, CounterType.packets) ids_flow;
    direct_counter(CounterType.packets_and_bytes) ids_rule_hit_counter;

    bool is_ids_listed;
    bool forward_to_ids;

    // ids_list ip
    register<bit<1>>(255) bf_new_flows1;
    register<bit<1>>(255) bf_new_flows2;
    register<bit<1>>(255) bf_new_flows3;
    register<bit<1>>(255) bf_new_flows4;

    register<bit<8>>(255) cm_limiter1;
    register<bit<8>>(255) cm_limiter2;
    register<bit<8>>(255) cm_limiter3;
    register<bit<8>>(255) cm_limiter4;

    bit<8> current_min = 0;
    bit<8> MAX_PACKETS = 20;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action pass(bit<9> port) {
        meta.redirect_to_ids = false;
    }

    action redirect(bit<9> port) {
        meta.redirect_to_ids = true;
    }
    
    action increment_cm_limiter(bit<32> src_ip, bit<32> dst_ip, bit<16> src_port, bit<16> dst_port, bit<8> protocol) {
        bit<8> flow_hash1;
        bit<8> flow_hash2;
        bit<8> flow_hash3;
        bit<8> flow_hash4;

        hash(flow_hash1, HashAlgorithm.crc16, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash2, HashAlgorithm.csum16, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash3, HashAlgorithm.crc16_custom, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash4, HashAlgorithm.crc32, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);

        bit<8> aux_counter;
        cm_limiter1.read(aux_counter, (bit<32>)flow_hash1);
        // Update count min row 1
        log_msg("cm_limiter1 new value {}", {aux_counter + 1});
        cm_limiter1.write((bit<32>)flow_hash1, aux_counter < MAX_PACKETS ? aux_counter + 1 : MAX_PACKETS);
        // Update count min row 2
        cm_limiter2.read(aux_counter, (bit<32>)flow_hash2);
        log_msg("cm_limiter2 new value {}", {aux_counter + 1});
        cm_limiter2.write((bit<32>)flow_hash2, aux_counter < MAX_PACKETS ? aux_counter + 1 : MAX_PACKETS);
        // Update count min row 3
        cm_limiter3.read(aux_counter, (bit<32>)flow_hash3);
        log_msg("cm_limiter3 new value {}", {aux_counter + 1});
        cm_limiter3.write((bit<32>)flow_hash3, aux_counter < MAX_PACKETS ? aux_counter + 1 : MAX_PACKETS);
        // Update count min row 4
        cm_limiter4.read(aux_counter, (bit<32>)flow_hash4);
        log_msg("cm_limiter4 new value {}", {aux_counter + 1});
        cm_limiter4.write((bit<32>)flow_hash4, aux_counter < MAX_PACKETS ? aux_counter + 1 : MAX_PACKETS);
    }

    action read_cm_limiter(bit<32> src_ip, bit<32> dst_ip, bit<16> src_port, bit<16> dst_port, bit<8> protocol) {
        bit<8> flow_hash1;
        bit<8> flow_hash2;
        bit<8> flow_hash3;
        bit<8> flow_hash4;
        bit<32> ackNo = hdr.tcp.ackNo-1;
        hash(flow_hash1, HashAlgorithm.crc16, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash2, HashAlgorithm.csum16, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash3, HashAlgorithm.crc16_custom, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash4, HashAlgorithm.crc32, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);

        current_min = 0xFF;
        bit<8> aux;
        cm_limiter1.read(aux, (bit<32>)flow_hash1);
        current_min = aux < current_min ? aux : current_min;

        cm_limiter2.read(aux, (bit<32>)flow_hash2);
        current_min = aux < current_min ? aux : current_min;

        cm_limiter3.read(aux, (bit<32>)flow_hash3);
        current_min = aux < current_min ? aux : current_min;

        cm_limiter4.read(aux, (bit<32>)flow_hash4);
        current_min = aux < current_min ? aux : current_min;

        log_msg("cm_limiter minimum value {}", {current_min});
    }

    action track_ongoing_flows(bit<32> src_ip, bit<32> dst_ip, bit<16> src_port, bit<16> dst_port, bit<8> protocol) {
        bit<8> flow_hash1;
        bit<8> flow_hash2;
        bit<8> flow_hash3;
        bit<8> flow_hash4;

        hash(flow_hash1, HashAlgorithm.crc16, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash2, HashAlgorithm.csum16, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash3, HashAlgorithm.crc16_custom, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);
        hash(flow_hash4, HashAlgorithm.crc32, 8w0, {src_ip, dst_ip, src_port, dst_port, protocol}, 8w0xFE);

        bf_new_flows1.write((bit<32>) flow_hash1, 1);
        bf_new_flows2.write((bit<32>) flow_hash2, 1);
        bf_new_flows3.write((bit<32>) flow_hash3, 1);
        bf_new_flows4.write((bit<32>) flow_hash4, 1);
    }

    action age_bloomfilter() {
        bit<1> has_usage;
        bit<8> current_value;
        
        bf_new_flows1.read(has_usage, 0);
        cm_limiter1.read(current_value, 0);
        cm_limiter1.write(0, has_usage == 0 ? 0 : current_value);
        bf_new_flows1.read(has_usage, 1);
        cm_limiter1.read(current_value, 1);
        cm_limiter1.write(1, has_usage == 0 ? 0 : current_value);
        bf_new_flows1.read(has_usage, 2);
        cm_limiter1.read(current_value, 2);
        cm_limiter1.write(2, has_usage == 0 ? 0 : current_value);
        bf_new_flows1.read(has_usage, 3);
        cm_limiter1.read(current_value, 3);
    }

    table ids {
        actions = {
            // Snort Actions
            //alert;
            //log;
            pass;
            drop;
            //reject;
            // P4Snort Proposed
            //mirror;
            // Defaut
            redirect;
            NoAction;
        }
        key = {
           hdr.ipv4.protocol: exact;
           hdr.ipv4.srcAddr: ternary;
           hdr.transport.srcPort: range;
           hdr.ipv4.dstAddr: ternary;
           hdr.transport.dstPort: range;
           hdr.transport.flags: ternary;
        }
        size = 10240;
        default_action = NoAction();
        counters = ids_rule_hit_counter;
    }

    table debug_table {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.transport.srcPort: exact;
            hdr.transport.dstPort: exact;
            hdr.ipv4.protocol: exact;
        }
        actions = {
        }
    }


    apply {
        received.count((bit<32>) standard_metadata.ingress_port);

        is_ids_listed = false;
        forward_to_ids = false;

        // Decide to forward or not
        if (hdr.ipv4.isValid()) {
            // check if is ids listed
            read_cm_limiter(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
                            hdr.transport.srcPort, hdr.transport.dstPort,
                            hdr.ipv4.protocol);
            // if is not ids listed
            if (current_min == 0) {
                // check if ids listed is needed
                ids.apply();
                if (meta.redirect_to_ids) {
                    ids_flow.count((bit<32>) 1);
                    forward_to_ids = true;
                }
            } else if (current_min < MAX_PACKETS) { // Already ids listed to be forwarded
                forward_to_ids = true;
            } else if (current_min >= MAX_PACKETS) {
                debug_table.apply();
                log_msg("Limit reached");
                forward_to_ids = false;
            }
        }

        if (forward_to_ids) {
            increment_cm_limiter(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
                   hdr.transport.srcPort, hdr.transport.dstPort,
                   hdr.ipv4.protocol);
            //increment_cm_limiter(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr,
            //               hdr.transport.dstPort, hdr.transport.srcPort,
            //               hdr.ipv4.protocol);

            track_ongoing_flows(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
               hdr.transport.srcPort, hdr.transport.dstPort,
               hdr.ipv4.protocol);
            standard_metadata.egress_spec = 1;
        } else {
            standard_metadata.egress_spec = 2;
        }

        standard_metadata.egress_spec = 1;

        timeout_aux.read(last_timestamp, 0);
        bit<48> time_diff = standard_metadata.ingress_global_timestamp - last_timestamp;
        if (time_diff > ONE_SECOND * 10) {
            log_msg("New timeout");
            timeout_aux.write(0, standard_metadata.ingress_global_timestamp); // update
            age_bloomfilter();
        }

        redirected.count((bit<32>) standard_metadata.egress_spec);
    }
}


V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
