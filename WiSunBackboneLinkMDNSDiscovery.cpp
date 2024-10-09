/**
 * @author Yann Charbon <yann.charbon@heig-vd.ch>
 * @copyright 2024
 */

#include "WiSunBackboneLinkMDNSDiscovery.h"

#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "BBLD"

WiSunBackboneLinkMDNSDiscovery::WiSunBackboneLinkMDNSDiscovery(const char *wisun_network_name) {
    snprintf(_service_name, 63, "WS-BR:%s", wisun_network_name);
    _bb_prot_stack = NULL;
}

int WiSunBackboneLinkMDNSDiscovery::StartServer() {
    int ret = 0;

    do {
        ThisThread::sleep_for(4s);
        _bb_prot_stack = protocol_stack_interface_info_get(IF_IPV6);

        if (_bb_prot_stack == NULL) {
            tr_error("Could not start service (backhaul interface not available)");
            ret = -1;
            continue;
        }

        tr_info("Starting '%s' mDNS service", _service_name);

        ns_mdns_t pMdns = ns_mdns_server_start(_service_name, 0, 0, _bb_prot_stack->id);
        if (pMdns == NULL) {
            tr_error("MDNS could not be started\n");
            ret = -1;
            continue;
        }
        tr_info("MDNS server started");

        ns_mdns_service_param_t srvParams;
        srvParams.service_type = "WsBBLink";
        srvParams.service_port = 30156;
        srvParams.service_get_txt = WsBBLinkGetServiceTXT;

        ns_mdns_service_t pMdnsService = ns_mdns_service_register(pMdns, &srvParams);
        if (pMdnsService == NULL) {
            tr_error("MDNS service could not be registered\n");
            ret = -1;
            continue;
        }
        tr_info("MDNS service added");
        ret = 0;
    } while (ret);

    return ret;
}

const uint8_t * WiSunBackboneLinkMDNSDiscovery::WsBBLinkGetServiceTXT(void) {
    static char txt[50] = " Wi-SUN Backbone link service";
    txt[0] = strlen(txt) - 1;
    return (const uint8_t *)txt;
}

int WiSunBackboneLinkMDNSDiscovery::Discover(NetworkInterface *bb_iface, SocketAddress& mbr_addr) {
    int ret = 0;

    do {
        _bb_prot_stack = protocol_stack_interface_info_get(IF_IPV6);

        if (_bb_prot_stack == NULL) {
            tr_error("Could not start service (backhaul interface not available)");
            ret = -1;
            ThisThread::sleep_for(4s);
            continue;
        }

        ret = 0;
    } while (ret);

    ret = _udp_socket.open(bb_iface);
    if (ret) {
        tr_error("Could not open UDP socket (%d)", ret);
    }
    ret = _udp_socket.setsockopt(SOCKET_IPPROTO_IPV6, SOCKET_INTERFACE_SELECT, &_bb_prot_stack->id, sizeof(_bb_prot_stack->id));
    if (ret) {
        tr_error("Could not bind socket to backhaul iface (unicast) (%d)", ret);
    }
    ret = _udp_socket.setsockopt(SOCKET_IPPROTO_IPV6, SOCKET_IPV6_MULTICAST_IF, &_bb_prot_stack->id, sizeof(_bb_prot_stack->id));
    if (ret) {
        tr_error("Could not bind socket to backhaul iface (multicast) (%d)", ret);
    }

    uint8_t query[256];
    memset(query, 0, 256);

    int idx = 0;

    // DNS query following https://datatracker.ietf.org/doc/html/rfc1035

    // Header
    query[idx++] = 0x00;     // Transaction ID 15-8
    query[idx++] = 0x00;     // Transaction ID 7-0
    query[idx++] = 0x00;     // Flags 15-8
    query[idx++] = 0x00;     // Flags 7-0
    query[idx++] = 0x00;     // Question count 15-8
    query[idx++] = 0x01;     // Question count 7-0
    query[idx++] = 0x00;     // Answer RRs 15-8
    query[idx++] = 0x00;     // Answer RRs 7-0
    query[idx++] = 0x00;     // Authority RRs 15-8
    query[idx++] = 0x00;     // Authority RRs 7-0
    query[idx++] = 0x00;     // Additional RRs 15-8
    query[idx++] = 0x00;     // Additional RRs 7-0

    // Question
    query[idx++] = strlen(_service_name);
    strcpy((char *)&query[idx], _service_name);
    idx += query[idx - 1];
    query[idx++] = strlen("WsBBLink");
    strcpy((char *)&query[idx], "WsBBLink");
    idx += query[idx - 1];
    query[idx++] = strlen("local");
    strcpy((char *)&query[idx], "local");
    idx += query[idx - 1];
    query[idx++] = '\0';    // 0 terminated string
    query[idx++] = 0x00;    // RR TYPE (QTYPE = A request for all records) 15-8
    query[idx++] = 0xFF;    // RR TYPE (QTYPE = A request for all records) 7-0
    query[idx++] = 0x00;    // RR CLASS (IN = The Internet) 15-8
    query[idx++] = 0x01;    // RR CLASS (IN = The Internet) 7-0

    _udp_socket.set_blocking(true);
    _udp_socket.set_timeout(3000);

    SocketAddress multicast_address("FF02::FB", 5353);

    tr_info("Sending mDNS QUERY");
    _udp_socket.sendto(multicast_address, query, idx);

    SocketAddress addr;
    uint8_t data[256];
    ret = _udp_socket.recvfrom(&addr, data, 256);
    if (ret > 0) {
        tr_info("UDP receive %d byte(s) from %s", ret, addr.get_ip_address());

        int idx = 0;
        idx += 2;   // Skip transaction ID
        if (data[idx] & 0x01 != 1) {
            tr_warn("Packet is not a DNS response");
            return -1; // Message is not a response
        }
        idx += 2;
        idx += 2;   // Skip QDCOUNT
        uint16_t answer_count = common_read_16_bit(&data[idx]);
        tr_debug("%d answer(s) detected in DNS query response", answer_count);
        idx += 2;
        idx += 2;   // Skip NSCOUNT
        idx += 2;   // Skip ARCOUNT

        if (answer_count == 0) {
            tr_warn("No answer detected in this response");
            return -1;
        }

        /// @todo improve robustness of this
        // Parse service name
        char parsed_name[63];
        memset(parsed_name, 0, 63);
        memcpy(parsed_name, &data[idx+1], data[idx++]);
        data[idx] = '\0';

        if (strcmp(parsed_name, _service_name) == 0) {
            tr_info("Successfully identified '%s' at address %s. Service READY.", parsed_name, addr.get_ip_address());
            memcpy(&mbr_addr, &addr, sizeof(mbr_addr));
            return 0;
        }
    }

    return -1;
}
