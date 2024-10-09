/**
 * @author Yann Charbon <yann.charbon@heig-vd.ch>
 * @copyright 2024
 */

#ifndef WISUN_BACKBONE_LINK_MBR_DISCOVERY_INTERFACE_H
#define WISUN_BACKBONE_LINK_MBR_DISCOVERY_INTERFACE_H

#include <stdint.h>
#include "mbed.h"
#include "NetworkInterface.h"

class IWiSunBackboneLinkMBRDiscovery {
public:
    virtual int StartServer() = 0;
    virtual int Discover(NetworkInterface *bb_iface, SocketAddress& mbr_addr) = 0;
    virtual ~IWiSunBackboneLinkMBRDiscovery() = default;
};

#endif