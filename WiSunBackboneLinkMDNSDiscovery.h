/**
 * @author Yann Charbon <yann.charbon@heig-vd.ch>
 * @copyright 2024
 */

#ifndef WISUN_BACKBONE_LINK_MDNS_DISCOVERY_H
#define WISUN_BACKBONE_LINK_MDNS_DISCOVERY_H

#include "IWiSunBackboneLinkMBRDiscovery.h"
#include "mbed.h"
#include "NetworkInterface.h"
#include "EthernetInterface.h"

extern "C" {
#include "ns_mdns_api.h"
#include "nsconfig.h"
#include "NWK_INTERFACE/Include/protocol.h"
#include "socket_api.h"
#include "common_functions.h"
}

class WiSunBackboneLinkMDNSDiscovery : public IWiSunBackboneLinkMBRDiscovery {
public:
    WiSunBackboneLinkMDNSDiscovery(const char *wisun_network_name);

    int StartServer() override;
    static const uint8_t * WsBBLinkGetServiceTXT(void);

    int Discover(NetworkInterface *bb_iface, SocketAddress& mbr_addr) override;

private:
    char _service_name[63];
    protocol_interface_info_entry_t *_bb_prot_stack;
    UDPSocket _udp_socket;
};

#endif // WISUN_BACKBONE_LINK_MDNS_DISCOVERY_H
