/**
 * @author Yann Charbon <yann.charbon@heig-vd.ch>
 * @copyright 2024
 */

#ifndef WISUN_BACKBONE_LINK_SERVICE_H
#define WISUN_BACKBONE_LINK_SERVICE_H

#include "mbed.h"
#include "NetworkInterface.h"
#include "EthernetInterface.h"

#include "IWiSunBackboneLinkService.h"
#include "WiSunBackboneLinkPhyInterceptor.h"
#include "IWiSunBackboneLinkMBRDiscovery.h"

extern "C" {
#include "ns_mdns_api.h"

#include "nsconfig.h"
#include "NWK_INTERFACE/Include/protocol.h"

#include "socket_api.h"
#include "common_functions.h"
}

class WiSunBackboneLinkService : IWiSunBackboneLinkService {
public:
    enum class Role {MASTER_BR, BACKBONE_NODE};

    static constexpr std::chrono::seconds ENDPOINTS_VALIDITY_CHECK_INTERVAL = std::chrono::seconds(30);
    static constexpr std::chrono::seconds INVALID_ENDPOINTS_CLEAR_DELAY = std::chrono::seconds(5);

    WiSunBackboneLinkService(IWiSunBackboneLinkMBRDiscovery* mbr_discovery);

    int start(const char *wisun_network_name, Role role);

    int SendPHYToMatchingClientAsync(uint8_t *dst_mac, bool broadcast, bool is_new_frame, uint8_t *data, uint16_t len) override;
    int SendPHYToMatchingClient(uint8_t *dst_mac, uint8_t *data, uint16_t len) override;
    bool CheckIfDstMACIsAnEndpoint(uint8_t *dst_mac) override;

    uint8_t * GetWiSunMacAddress() override;
private:
    enum class State {MBR_DISCOVERY, BB_LINK_ESTABLISH, BB_LINK_EXCHANGE_MAC_ADDR, BBLINK_READY, BBLINK_ERROR};
    State _state;

    enum class CtrlMessageType {WS_MAC_ADDR_IND_REQ = 0x1, PRESENCE_CHECK_REQ = 0x2, PRESENCE_CHECK_RES = 0x3};

    class Data {
    public:
        ~Data() {
            deallocate();
        }

        int allocate(uint16_t data_len) {
            data = (uint8_t *)calloc(data_len, sizeof(uint8_t));
            if (!data) {
                return -1;
            }
            return 0;
        }

        void deallocate() {
            if (data) {
                free(data);
                data = NULL;
            }
        }

        uint8_t dst_mac[8];
        uint8_t *data;
        uint16_t len;
    };

    Role _role;
    Thread _state_thread, _send_thread, _recv_thread;
    Queue<Data, 64> _send_queue;
    Queue<Data, 64> _recv_queue;
    static uint8_t _recv_buffer[1500];
    Timer _send_duplicate_avoidance_timer;
    bool _prev_data_was_broadcasted;
    protocol_interface_info_entry_t *_bb_prot_stack;
    static protocol_interface_info_entry_t *_ws_prot_stack;
    NetworkInterface *bb_iface;
    UDPSocket _uplink_sock, _downlink_sock;
    SocketAddress _master_br_sock_addr;
    Timer _endpoints_validity_timer;
    std::chrono::seconds _last_endpoints_validity_check;
    bool _validity_check_started;

    WiSunBackboneLinkPhyInterceptor& _interceptor;
    IWiSunBackboneLinkMBRDiscovery *_mbr_discovery;

    class BBLinkEndPoint {
    public:
        BBLinkEndPoint() {
            idx = -1;
            memset(mac, 0, 8);
        }

        BBLinkEndPoint(int index, uint8_t *clientMac, SocketAddress& clientAddr) {
            idx = index;
            memcpy(mac, clientMac, 8);
            memcpy(&addr, &clientAddr, sizeof(addr));
        }

        int idx;
        uint8_t mac[8];
        SocketAddress addr;
        std::chrono::seconds last_rx_timestamp;
    };

    BBLinkEndPoint _master_br_endpoint;
    static BBLinkEndPoint *_end_point_list[32];

    int _getFirstUnusedEndpointSlot();
    int _getEndPointsCount();
    BBLinkEndPoint * _findEndPointByAddress(SocketAddress& addr);
    void _removeAndCloseEndPoint(int idx);

    void _SendThreadTask();
    void _RecvThreadTask();

    void _stateThreadTask();

    int _DiscoverMasterBR();
    int _establishBBLink();
    int _exchangeMacAddr();
    void _triggerEnpointsValidityCheck();
    void _cleanInvalidEndpoints();
    void _ReceiveFromBBLink();
};

#endif