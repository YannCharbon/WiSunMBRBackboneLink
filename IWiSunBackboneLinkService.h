/**
 * @author Yann Charbon <yann.charbon@heig-vd.ch>
 * @copyright 2024
 */

#ifndef WISUN_BACKBONE_LINK_SERVICE_INTERFACE_H
#define WISUN_BACKBONE_LINK_SERVICE_INTERFACE_H

#include <stdint.h>

class IWiSunBackboneLinkService {
public:
    virtual int SendPHYToMatchingClient(uint8_t *dst_mac, uint8_t *data, uint16_t len) = 0;
    virtual int SendPHYToMatchingClientAsync(uint8_t *dst_mac, bool broadcast, bool is_new_frame, uint8_t *data, uint16_t len) = 0;
    virtual bool CheckIfDstMACIsAnEndpoint(uint8_t *dst_mac) = 0;
    virtual uint8_t * GetWiSunMacAddress() = 0;
    virtual ~IWiSunBackboneLinkService() = default;
};

#endif