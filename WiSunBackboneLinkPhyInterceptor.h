/**
 * @author Yann Charbon <yann.charbon@heig-vd.ch>
 * @copyright 2024
 */

#ifndef WISUN_BACKBONE_LINK_PHY_INTERCEPTOR_H
#define WISUN_BACKBONE_LINK_PHY_INTERCEPTOR_H

#include "mbed.h"

#include "IWiSunBackboneLinkService.h"

extern "C" {
#include "nsconfig.h"
#include "NWK_INTERFACE/Include/protocol.h"
#include "arm_hal_phy.h"
#include "rf_driver_storage.h"
#include "common_functions.h"
}

class WiSunBackboneLinkPhyInterceptor {
public:
    enum class FrameType {PA, PAS, PC, PCS, OTHER};

    static WiSunBackboneLinkPhyInterceptor& GetInstance();

    // Prevent moving or copying this instance
    WiSunBackboneLinkPhyInterceptor(const WiSunBackboneLinkPhyInterceptor&) = delete;
    WiSunBackboneLinkPhyInterceptor(WiSunBackboneLinkPhyInterceptor&&) = delete;
    WiSunBackboneLinkPhyInterceptor& operator=(const WiSunBackboneLinkPhyInterceptor&) = delete;
    WiSunBackboneLinkPhyInterceptor& operator=(WiSunBackboneLinkPhyInterceptor&&) = delete;

    void SetBBLinkService(IWiSunBackboneLinkService* service);
    int RegisterInterceptor();
    void InjectRxData(uint8_t *data, uint16_t len);

private:
    enum class SendInterface {BOTH, RF, BBLINK};

    static int _orig_phy_driver_id;
    static phy_device_driver_s _orig_phy_driver;
    static phy_device_driver_s *_interceptor_driver;
    static IWiSunBackboneLinkService *_service;
    static FrameType _prev_frame_type;

    // Prevent using constructor and destructor as it is a singleton class
    WiSunBackboneLinkPhyInterceptor() {}
    ~WiSunBackboneLinkPhyInterceptor() {}

    void _InsertPhyInterceptor();
    static void _fake_ack_reception(uint8_t *fake_src_mac, uint8_t *dst_mac, uint8_t seq_number);
    static int8_t _start_cca_override(uint8_t *data_ptr, uint16_t data_length, uint8_t tx_handle, data_protocol_e data_protocol);
    static int8_t _arm_net_phy_rx_fn_override(const uint8_t *data_ptr, uint16_t data_len, uint8_t link_quality, int8_t dbm, int8_t driver_id);
    static int8_t _arm_net_phy_tx_done_fn_override(int8_t driver_id, uint8_t tx_handle, phy_link_tx_status_e status, uint8_t cca_retry, uint8_t tx_retry);
};

#endif // WISUN_BACKBONE_LINK_PHY_INTERCEPTOR_H
