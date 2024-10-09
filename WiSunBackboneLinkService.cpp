/**
 * @author Yann Charbon <yann.charbon@heig-vd.ch>
 * @copyright 2024
 */

#include "WiSunBackboneLinkService.h"


#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "BBLS"

constexpr std::chrono::seconds WiSunBackboneLinkService::ENDPOINTS_VALIDITY_CHECK_INTERVAL;
constexpr std::chrono::seconds WiSunBackboneLinkService::INVALID_ENDPOINTS_CLEAR_DELAY;

protocol_interface_info_entry_t* WiSunBackboneLinkService::_ws_prot_stack = nullptr;
WiSunBackboneLinkService::BBLinkEndPoint* WiSunBackboneLinkService::_end_point_list[32] = {nullptr};
uint8_t WiSunBackboneLinkService::_recv_buffer[1500];

WiSunBackboneLinkService::WiSunBackboneLinkService(IWiSunBackboneLinkMBRDiscovery* mbr_discovery) :
    _state_thread(osPriorityAboveNormal, OS_STACK_SIZE, nullptr, "WsBBLinkThread"),
    _send_thread(osPriorityHigh, OS_STACK_SIZE, nullptr, "WsBBLinkSendThread"),
    _recv_thread(osPriorityHigh, OS_STACK_SIZE, nullptr, "WsBBLinkRecvThread"),
    _send_queue(),
    _recv_queue(),
    _state(State::MBR_DISCOVERY),
    _interceptor(WiSunBackboneLinkPhyInterceptor::GetInstance()),
    _prev_data_was_broadcasted(false),
    _validity_check_started(false),
    _mbr_discovery(mbr_discovery) {

    _interceptor.SetBBLinkService(this);
    _endpoints_validity_timer.start();
}

int WiSunBackboneLinkService::start(const char *wisun_network_name, Role role) {
    int ret;

    _role = role;


    bb_iface = EthInterface::get_default_instance();
    if (bb_iface == NULL) {
        tr_error("Could not get default interface");
        return -1;
    }

    if (_role == Role::BACKBONE_NODE) {
        // Master border-router does not need to do this because it is already managed by the border-router itself.
        ret = bb_iface->connect();
        if (ret) {
            tr_error("Could not connect BB iface (%d)", ret);
            return ret;
        }
    }

    do {
        ThisThread::sleep_for(4s);
        _bb_prot_stack = protocol_stack_interface_info_get(IF_IPV6);

        if (_bb_prot_stack == NULL) {
            tr_error("Could not start service (backhaul interface not available)");
            ret = -1;
            continue;
        }

        if (_role == Role::MASTER_BR) {
            ret = _mbr_discovery->StartServer();
            if (ret) {
                tr_error("Could not start Discovery service");
            }
        }
    } while(ret);

    _state_thread.start(callback(this, &WiSunBackboneLinkService::_stateThreadTask));
    _send_thread.start(callback(this, &WiSunBackboneLinkService::_SendThreadTask));
    _recv_thread.start(callback(this, &WiSunBackboneLinkService::_RecvThreadTask));

    return 0;
}

int WiSunBackboneLinkService::SendPHYToMatchingClientAsync(uint8_t *dst_mac, bool broadcast, bool is_new_frame, uint8_t *data, uint16_t len) {  // override
    // We don't need to send multiple times the same packet. This can happen when a packet is broadcasted over all FHSS channels. Observation window is 3s.
    if (!is_new_frame && _send_duplicate_avoidance_timer.elapsed_time() < 3s && _prev_data_was_broadcasted && broadcast) {
        _send_duplicate_avoidance_timer.reset();
        return 0;
    }
    _send_duplicate_avoidance_timer.reset();
    if (broadcast) {
        _prev_data_was_broadcasted = true;
    } else {
        _prev_data_was_broadcasted = false;
    }

    //tr_warn("PS");

    Data *send_data = new Data();
    if (send_data->allocate(len) != 0) {
        tr_error("Could not allocate send data");
        return -1;
    }
    if (dst_mac != NULL) {
        memcpy(send_data->dst_mac, dst_mac, 8);
    } else {
        memset(send_data->dst_mac, 0, 8);
    }
    memcpy(send_data->data, data, len);
    send_data->len = len;

    if (_send_queue.try_put(send_data) == false) {
        tr_error("Could not push to send queue");
        return -1;
    }
    return 0;
}

int WiSunBackboneLinkService::SendPHYToMatchingClient(uint8_t *dst_mac, uint8_t *data, uint16_t len) {  // override
    int ret;

    //tr_info("Trying to send data of len = %d", len);

    if (_role == Role::BACKBONE_NODE) {
        for (int tries = 2; tries > 0; tries--) {
            if ((ret = _uplink_sock.sendto(_master_br_endpoint.addr, data, len)) >= NSAPI_ERROR_OK) {
                break;
            }
            tr_warn("Could not send to %s:%d (%d)", _master_br_endpoint.addr.get_ip_address(), _master_br_endpoint.addr.get_port(), ret);
            if (ret != NSAPI_ERROR_WOULD_BLOCK) {
                ThisThread::sleep_for(500ms);
            } else {
                ThisThread::sleep_for(10ms);
                tries++;
            }
        }
        if (ret < 0) {
            tr_error("Could not send PHY data to MBR (%d)", ret);
        }
        return ret;
    } else if (_role == Role::MASTER_BR) {
        int endpoints_count = _getEndPointsCount();

        if (endpoints_count == 0) {
            return 0;   // No client registered. Considering this as a success.
        }

        uint8_t empty_mac[8];
        memset(empty_mac, 0, 8);

        for (int i = 0; i < sizeof(_end_point_list) / sizeof(_end_point_list[0]); i++) {
            if (_end_point_list[i] == NULL) {
                continue;
            }
            if (memcmp(dst_mac, empty_mac, 8) == 0) {
                for (int tries = 2; tries > 0; tries--) {
                    if ((ret = _downlink_sock.sendto(_end_point_list[i]->addr, data, len)) >= NSAPI_ERROR_OK) {
                        break;
                    }
                    tr_warn("Could not send (%d)", ret);
                    if (ret != NSAPI_ERROR_WOULD_BLOCK) {
                        ThisThread::sleep_for(500ms);
                    } else {
                        ThisThread::sleep_for(10ms);
                        tries++;
                    }
                }
                if (ret < 0) {
                    tr_warn("Could not send PHY data to BB node %s (%d, %d)", _end_point_list[i]->addr.get_ip_address(), ret);
                    _removeAndCloseEndPoint(i);
                }
            } else if (memcmp(_end_point_list[i]->mac, dst_mac, 8) == 0) {
                for (int tries = 2; tries > 0; tries--) {
                    if ((ret = _downlink_sock.sendto(_end_point_list[i]->addr, data, len)) >= NSAPI_ERROR_OK) {
                        break;
                    }
                    tr_warn("Could not send (%d)", ret);
                    if (ret != NSAPI_ERROR_WOULD_BLOCK) {
                        ThisThread::sleep_for(500ms);
                    } else {
                        ThisThread::sleep_for(10ms);
                        tries++;
                    }
                }
                if (ret < 0) {
                    tr_error("Could not send PHY data to BB node %s (%d)", _end_point_list[i]->addr.get_ip_address(), ret);
                    _removeAndCloseEndPoint(i);
                }
                return ret;
            }
        }
        if (memcmp(dst_mac, empty_mac, 8) != 0) {
            tr_error("No matching BB link node for this MAC: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",  dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3],
                                                                                                        dst_mac[4], dst_mac[5], dst_mac[6], dst_mac[7]);
            for (int i = 0; i < len; i++) {
                printf("%02X ", data[i]);
            }
            printf("\n");
        } else {
            return 0;   // Broadcast is always considered as a success
        }
    }

    return -1;
}

bool WiSunBackboneLinkService::CheckIfDstMACIsAnEndpoint(uint8_t *dst_mac) {  // override
    if (_role == Role::BACKBONE_NODE) {
        if (memcmp(_master_br_endpoint.mac, dst_mac, 8) == 0) {
            return true;
        }
    } else if (_role == Role::MASTER_BR) {
        for (int i = 0; i < sizeof(_end_point_list) / sizeof(_end_point_list[0]); i++) {
            if (memcmp(_end_point_list[i]->mac, dst_mac, 8) == 0)  {
                return true;
            }
        }
    }

    return false;
}

uint8_t* WiSunBackboneLinkService::GetWiSunMacAddress() {   // override
    if (_ws_prot_stack && _ws_prot_stack->mac) {
        return _ws_prot_stack->mac;
    }

    return NULL;
}

int WiSunBackboneLinkService::_getFirstUnusedEndpointSlot() {
    int idx = 0;
    while (_end_point_list[idx++] != NULL);
    return idx - 1;
}

int WiSunBackboneLinkService::_getEndPointsCount() {
    int count = 0;
    for (int i = 0; i < sizeof(_end_point_list) / sizeof(_end_point_list[0]); i++) {
        if (_end_point_list[i] != NULL) {
            count++;
        }
    }
    return count;
}

WiSunBackboneLinkService::BBLinkEndPoint * WiSunBackboneLinkService::_findEndPointByAddress(SocketAddress& addr) {
    for (int i = 0; i < sizeof(_end_point_list) / sizeof(_end_point_list[0]); i++) {
        if (memcmp(_end_point_list[i]->addr.get_ip_bytes(), addr.get_ip_bytes(), 16) == 0) {
            return _end_point_list[i];
        }
    }
    return nullptr;
}

void WiSunBackboneLinkService::_removeAndCloseEndPoint(int idx) {
    tr_error("Deleting endpoint at index %d", idx);
    if (_end_point_list[idx]) {
        tr_info("A");

        delete _end_point_list[idx];
        _end_point_list[idx] = NULL;
        tr_info("E");
    }
}

void WiSunBackboneLinkService::_SendThreadTask() {
    Data *send_data;

    _send_duplicate_avoidance_timer.start();

    while (1) {
        if (_send_queue.try_get_for(5s, &send_data) == true) {
            // In any case, we extract a packet at least every 2s. This acts as a expiration timeout for the packet.
            if (_state == State::BBLINK_READY) {
                //tr_warn("1");
                    //tr_warn("A");
                    SendPHYToMatchingClient(send_data->dst_mac, send_data->data, send_data->len);
                    //tr_warn("B");
                    send_data->deallocate();
                    //tr_warn("C");
                    delete send_data;

            } else {
                ThisThread::sleep_for(2s);
            }
        }
    }
}

void WiSunBackboneLinkService::_RecvThreadTask() {
    Data *recv_data;

    while (1) {
        if (_recv_queue.try_get_for(10s, &recv_data) == true) {
            _interceptor.InjectRxData(recv_data->data, recv_data->len);
            recv_data->deallocate();
            delete recv_data;
        }
    }
}

void WiSunBackboneLinkService::_stateThreadTask() {
    int ret;

    do {
        ret = _interceptor.RegisterInterceptor();
        if (ret) {
            tr_warn("Could not register interceptor. Retrying in 2s");
            ThisThread::sleep_for(2s);
        }
    } while(ret);

    while (1) {
        if (_ws_prot_stack == NULL) {
            _ws_prot_stack = protocol_stack_interface_info_get(IF_6LoWPAN);
        }

        if (_state == State::MBR_DISCOVERY) {
            if (_role == Role::BACKBONE_NODE) {
                while (_state == State::MBR_DISCOVERY) {
                    ret = _DiscoverMasterBR();
                    if (ret == 0) {
                        _state = State::BB_LINK_ESTABLISH;
                    } else {
                        ThisThread::sleep_for(20s);
                    }
                }
            } else if (_role == Role::MASTER_BR) {
                _state = State::BB_LINK_ESTABLISH;
                ThisThread::sleep_for(1s);
            }
        }

        if (_state == State::BB_LINK_ESTABLISH) {
            ret = _establishBBLink();
            if (ret == 0) {
                if (_role == Role::BACKBONE_NODE) {
                    _state = State::BB_LINK_EXCHANGE_MAC_ADDR;
                } else {
                    _state = State::BBLINK_READY;
                    _last_endpoints_validity_check = std::chrono::duration_cast<std::chrono::seconds>(_endpoints_validity_timer.elapsed_time());
                }
            } else {
                _state = State::MBR_DISCOVERY;
            }
        }

        if (_state == State::BB_LINK_EXCHANGE_MAC_ADDR) {
            ret = _exchangeMacAddr();
            if (ret) {
                _state = State::MBR_DISCOVERY;
            } else {
                _state = State::BBLINK_READY;
                _last_endpoints_validity_check = std::chrono::duration_cast<std::chrono::seconds>(_endpoints_validity_timer.elapsed_time());
            }
        }

        if (_state == State::BBLINK_READY) {

            if (_endpoints_validity_timer.elapsed_time() > _last_endpoints_validity_check + ENDPOINTS_VALIDITY_CHECK_INTERVAL && !_validity_check_started) {
                _triggerEnpointsValidityCheck();
                _validity_check_started = true;
                _last_endpoints_validity_check = std::chrono::duration_cast<std::chrono::seconds>(_endpoints_validity_timer.elapsed_time());
            }

            if (_endpoints_validity_timer.elapsed_time() > _last_endpoints_validity_check + INVALID_ENDPOINTS_CLEAR_DELAY && _validity_check_started) {
                _cleanInvalidEndpoints();

                _validity_check_started = false;
            }

            _ReceiveFromBBLink();
        }

        if (_state == State::BBLINK_ERROR) {
            _uplink_sock.close();
            _downlink_sock.close();
            _state = State::MBR_DISCOVERY;
        }
    }
}

int WiSunBackboneLinkService::_DiscoverMasterBR() {
    int ret = _mbr_discovery->Discover(bb_iface, _master_br_sock_addr);
    if (ret == 0) {
        _master_br_sock_addr.set_port(30155);
    }
    return ret;
}

int WiSunBackboneLinkService::_establishBBLink() {
    int ret;

    ret = _uplink_sock.open(bb_iface);
    if (ret) {
        tr_error("Could not open UPLINK socket (%d)", ret);
        return ret;
    }

    ret = _downlink_sock.open(bb_iface);
    if (ret) {
        tr_error("Could not open DOWNLINK socket (%d)", ret);
        return ret;
    }

    if (_role == Role::MASTER_BR) {
        ret = _uplink_sock.bind(30155);
        if (ret) {
            tr_error("Could not bind UPLINK socket to port 30155 (%d)", ret);
            _uplink_sock.close();
            return ret;
        }
    } else {
        ret = _downlink_sock.bind(30154);
        if (ret) {
            tr_error("Could not bind DOWNLINK socket to port 30154 (%d)", ret);
            _downlink_sock.close();
            return ret;
        }
    }

    ret = _uplink_sock.setsockopt(SOCKET_IPPROTO_IPV6, SOCKET_INTERFACE_SELECT, &_bb_prot_stack->id, sizeof(_bb_prot_stack->id));
    if (ret) {
        tr_error("Could not bind UPLINK socket to backhaul iface (unicast) (%d)", ret);
    }
    ret = _uplink_sock.setsockopt(SOCKET_IPPROTO_IPV6, SOCKET_IPV6_MULTICAST_IF, &_bb_prot_stack->id, sizeof(_bb_prot_stack->id));
    if (ret) {
        tr_error("Could not bind UPLINK socket to backhaul iface (multicast) (%d)", ret);
    }

    ret = _downlink_sock.setsockopt(SOCKET_IPPROTO_IPV6, SOCKET_INTERFACE_SELECT, &_bb_prot_stack->id, sizeof(_bb_prot_stack->id));
    if (ret) {
        tr_error("Could not bind DOWNLINK socket to backhaul iface (unicast) (%d)", ret);
    }
    ret = _downlink_sock.setsockopt(SOCKET_IPPROTO_IPV6, SOCKET_IPV6_MULTICAST_IF, &_bb_prot_stack->id, sizeof(_bb_prot_stack->id));
    if (ret) {
        tr_error("Could not bind DOWNLINK socket to backhaul iface (multicast) (%d)", ret);
    }

    tr_info("Successfully opened UPLINK/DOWNLINK Sockets");

    return 0;
}

int WiSunBackboneLinkService::_exchangeMacAddr() {
    int ret;
    uint8_t msg[50];
    memset(msg, 0, sizeof(msg));

    int idx = 0;
    msg[idx++] = 0xFF;
    msg[idx++] = (uint8_t)CtrlMessageType::WS_MAC_ADDR_IND_REQ;

    int timeout = 10;
    while (timeout--) {
        _ws_prot_stack = protocol_stack_interface_info_get(IF_6LoWPAN);
        if (_ws_prot_stack && _ws_prot_stack->mac) {
            memcpy(&msg[idx], _ws_prot_stack->mac, 8);
            idx += 8;
            break;
        }
        tr_debug("Could not get Wi-SUN MAC address. Retrying in 2s");
        ThisThread::sleep_for(2s);
    }

    if (timeout == 0) {
        tr_error("Could not get Wi-SUN MAC address.");
        return -1;
    }

    timeout = 10;
    while (timeout--) {
        ret = _uplink_sock.sendto(_master_br_sock_addr, msg, idx);
        if (ret < 0) {
            tr_error("Could not send (%d)", ret);
            ThisThread::sleep_for(1s);
            continue;
        }

        SocketAddress recvSockAddr;
        uint8_t resp[50];
        ret = _downlink_sock.recvfrom(&recvSockAddr, resp, 50);
        tr_warn("Received %d byte(s) from %s (%s)", ret, recvSockAddr.get_ip_address(), _master_br_sock_addr.get_ip_address());
        if (ret > 0 && memcmp(_master_br_sock_addr.get_ip_bytes(), recvSockAddr.get_ip_bytes(), 16) == 0) {
            if (resp[0] == 0xFF && resp[1] == (uint8_t)CtrlMessageType::WS_MAC_ADDR_IND_REQ) {
                memcpy(_master_br_endpoint.mac, &resp[2], 8);
                _master_br_endpoint.addr.set_port(30155);
                _master_br_endpoint.addr.set_ip_bytes(_master_br_sock_addr.get_ip_bytes(), NSAPI_IPv6);
                tr_info("Master BR Wi-SUN MAC: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",    _master_br_endpoint.mac[0], _master_br_endpoint.mac[1], _master_br_endpoint.mac[2], _master_br_endpoint.mac[3],
                                                                                            _master_br_endpoint.mac[4], _master_br_endpoint.mac[5], _master_br_endpoint.mac[6], _master_br_endpoint.mac[7]);
                tr_info("Own Wi-SUN MAC: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",          _ws_prot_stack->mac[0], _ws_prot_stack->mac[1], _ws_prot_stack->mac[2], _ws_prot_stack->mac[3],
                                                                                            _ws_prot_stack->mac[4], _ws_prot_stack->mac[5], _ws_prot_stack->mac[6], _ws_prot_stack->mac[7]);
                return 0;
            }
        }
    }

    tr_error("Failed to exchange MAC addresses");

    return -1;
}

void WiSunBackboneLinkService::_triggerEnpointsValidityCheck() {
    tr_info("Triggering endpoints validity check");
    if (_role == Role::BACKBONE_NODE) {
        if (_master_br_endpoint.last_rx_timestamp < _endpoints_validity_timer.elapsed_time() - ENDPOINTS_VALIDITY_CHECK_INTERVAL) {
            tr_info("Link to MBR might be broken. Sending PRESENCE_CHECK_REQ");
            Data *resp = new Data();
            if (resp->allocate(2) == 0) {
                // We respond using the whole send stack (involving queue, etc.) to make sure everything is working
                memcpy(resp->dst_mac, _master_br_endpoint.mac, 8);
                resp->data[0] = 0xFF;
                resp->data[1] = (uint8_t)CtrlMessageType::PRESENCE_CHECK_REQ;
                resp->len = 2;
                if (_send_queue.try_put(resp) == false) {
                    resp->deallocate();
                    delete resp;
                    tr_error("Could not push PRESENCE_CHECK_RES to send queue");
                }
            }
        }
    } else if (_role == Role::MASTER_BR) {
        for (int i = 0; i < sizeof(_end_point_list) / sizeof(_end_point_list[0]); i++) {
            if (_end_point_list[i] != nullptr) {
                if (_end_point_list[i]->last_rx_timestamp < _endpoints_validity_timer.elapsed_time() - ENDPOINTS_VALIDITY_CHECK_INTERVAL) {
                    tr_info("Link to endpoint %d might be broken. Sending PRESENCE_CHECK_REQ", i);
                    Data *resp = new Data();
                    if (resp->allocate(2) == 0) {
                        // We respond using the whole send stack (involving queue, etc.) to make sure everything is working
                        BBLinkEndPoint *endpoint = _end_point_list[i];
                        if (endpoint) {
                            memcpy(resp->dst_mac, endpoint->mac, 8);
                            resp->data[0] = 0xFF;
                            resp->data[1] = (uint8_t)CtrlMessageType::PRESENCE_CHECK_REQ;
                            resp->len = 2;
                            if (_send_queue.try_put(resp) == false) {
                                tr_error("Could not push PRESENCE_CHECK_REQ to send queue");
                            }
                        } else {
                            resp->deallocate();
                            delete resp;
                        }
                    }
                }
            }
        }
    }
}

void WiSunBackboneLinkService::_cleanInvalidEndpoints() {
    tr_info("Cleaning invalid endpoints");
    if (_role == Role::BACKBONE_NODE) {
        if (_master_br_endpoint.last_rx_timestamp < _endpoints_validity_timer.elapsed_time() - ENDPOINTS_VALIDITY_CHECK_INTERVAL - INVALID_ENDPOINTS_CLEAR_DELAY - 1s) {
            tr_warn("Link towards MBR is broken. Restarting connection.");
            _state = State::BBLINK_ERROR;
        }
    } else if (_role == Role::MASTER_BR) {
        for (int i = 0; i < sizeof(_end_point_list) / sizeof(_end_point_list[0]); i++) {
            if (_end_point_list[i] != nullptr) {
                if (_end_point_list[i]->last_rx_timestamp < _endpoints_validity_timer.elapsed_time() - ENDPOINTS_VALIDITY_CHECK_INTERVAL - INVALID_ENDPOINTS_CLEAR_DELAY - 1s) {
                    tr_warn("Endpoint %d (%s) is stale and will be removed", i, _end_point_list[i]->addr.get_ip_address());
                    _removeAndCloseEndPoint(i);
                }
            }
        }
    }
}

void WiSunBackboneLinkService::_ReceiveFromBBLink() {
    int ret;

    if (_role == Role::MASTER_BR) {
        _uplink_sock.set_blocking(true);
        _uplink_sock.set_timeout(2000);

        SocketAddress clientAddr;
        ret = _uplink_sock.recvfrom(&clientAddr, _recv_buffer, 1500);
        if (ret <= 0) {
            return;
        }

        //tr_warn("Received %d byte(s) from %s", ret, clientAddr.get_ip_address());

        if (_recv_buffer[0] == 0xFF && _recv_buffer[1] == (uint8_t)CtrlMessageType::WS_MAC_ADDR_IND_REQ) {
            tr_debug("Received WS_MAC_ADDR_IND_REQ");
            int idx;

            clientAddr.set_port(30154);

            // Check if endpoint is already registered
            BBLinkEndPoint *endPoint = _findEndPointByAddress(clientAddr);
            if (endPoint == nullptr) {
                int slot = _getFirstUnusedEndpointSlot();
                endPoint = new BBLinkEndPoint(idx, &_recv_buffer[2], clientAddr);
                // Adding to endpoints list
                _end_point_list[slot] = endPoint;
                tr_error("New endpoint inserted at index %d", idx);
            } else {
                // Update MAC address
                memcpy(endPoint->mac, &_recv_buffer[2], 8);
            }

            endPoint->last_rx_timestamp = std::chrono::duration_cast<std::chrono::seconds>(_endpoints_validity_timer.elapsed_time());

            tr_info("New BB node Wi-SUN MAC: %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",  endPoint->mac[0], endPoint->mac[1], endPoint->mac[2], endPoint->mac[3],
                                                                                        endPoint->mac[4], endPoint->mac[5], endPoint->mac[6], endPoint->mac[7]);

            // Response to the request
            uint8_t msg[50];
            memset(msg, 0, sizeof(msg));

            idx = 0;
            msg[idx++] = 0xFF;
            msg[idx++] = (uint8_t)CtrlMessageType::WS_MAC_ADDR_IND_REQ;

            int timeout = 10;
            _ws_prot_stack = protocol_stack_interface_info_get(IF_6LoWPAN);
            if (_ws_prot_stack && _ws_prot_stack->mac) {
                memcpy(&msg[idx], _ws_prot_stack->mac, 8);
                idx += 8;
            } else {
                tr_warn("Could not respond to client because Wi-SUN stack is not available");
                return;
            }

            ret = _downlink_sock.sendto(endPoint->addr, msg, idx);
            if (ret < 0) {
                tr_error("Could not send WS_MAC_ADDR_IND_REQ to client (%d)", ret);
                return;
            }

        } else if (_recv_buffer[0] == 0xFF && _recv_buffer[1] == (uint8_t)CtrlMessageType::PRESENCE_CHECK_REQ) {
            tr_info("Received PRESENCE_CHECK_REQ");
            Data *resp = new Data();
            if (resp->allocate(2) == 0) {
                // We respond using the whole send stack (involving queue, etc.) to make sure everything is working
                BBLinkEndPoint *endpoint = _findEndPointByAddress(clientAddr);
                if (endpoint) {
                    endpoint->last_rx_timestamp = std::chrono::duration_cast<std::chrono::seconds>(_endpoints_validity_timer.elapsed_time());
                    memcpy(resp->dst_mac, endpoint->mac, 8);
                    resp->data[0] = 0xFF;
                    resp->data[1] = (uint8_t)CtrlMessageType::PRESENCE_CHECK_RES;
                    resp->len = 2;
                    if (_send_queue.try_put(resp) == false) {
                        resp->deallocate();
                        delete resp;
                        tr_error("Could not push PRESENCE_CHECK_RES to send queue");
                    }
                } else {
                    resp->deallocate();
                    delete resp;
                }
            }
        } else if (_recv_buffer[0] == 0xFF && _recv_buffer[1] == (uint8_t)CtrlMessageType::PRESENCE_CHECK_RES) {
            tr_info("Received PRESENCE_CHECK_RES");
            BBLinkEndPoint *endpoint = _findEndPointByAddress(clientAddr);
            if (endpoint) {
                endpoint->last_rx_timestamp = std::chrono::duration_cast<std::chrono::seconds>(_endpoints_validity_timer.elapsed_time());
            }
        } else {
            BBLinkEndPoint *endpoint = _findEndPointByAddress(clientAddr);
            if (endpoint) {
                endpoint->last_rx_timestamp = std::chrono::duration_cast<std::chrono::seconds>(_endpoints_validity_timer.elapsed_time());
                WiSunBackboneLinkPhyInterceptor::GetInstance().InjectRxData(_recv_buffer, ret);
            } else {
                tr_warn("Received data from unknown endpoint. Ignoring.");
            }
        }
    } else if (_role == Role::BACKBONE_NODE) {
        _downlink_sock.set_blocking(true);
        _downlink_sock.set_timeout(2000);

        SocketAddress clientAddr;
        ret = _downlink_sock.recvfrom(&clientAddr, _recv_buffer, 1500);
        if (ret > 0) {
            if (strcmp(_master_br_endpoint.addr.get_ip_address(), clientAddr.get_ip_address()) == 0) {
                _master_br_endpoint.last_rx_timestamp = std::chrono::duration_cast<std::chrono::seconds>(_endpoints_validity_timer.elapsed_time());
                //tr_warn("Received %d byte(s) from MBR", ret);
                if (_recv_buffer[0] == 0xFF && _recv_buffer[1] == (uint8_t)CtrlMessageType::PRESENCE_CHECK_REQ) {
                    tr_info("Received PRESENCE_CHECK_REQ");
                    Data *resp = new Data();
                    if (resp->allocate(2) == 0) {
                        // We respond using the whole send stack (involving queue, etc.) to make sure everything is working
                        memcpy(resp->dst_mac, _master_br_endpoint.mac, 8);
                        resp->data[0] = 0xFF;
                        resp->data[1] = (uint8_t)CtrlMessageType::PRESENCE_CHECK_RES;
                        resp->len = 2;
                        if (_send_queue.try_put(resp) == false) {
                            resp->deallocate();
                            delete resp;
                            tr_error("Could not push PRESENCE_CHECK_RES to send queue");
                        }
                    }
                } else if (_recv_buffer[0] == 0xFF && _recv_buffer[1] == (uint8_t)CtrlMessageType::PRESENCE_CHECK_RES) {
                    tr_info("Received PRESENCE_CHECK_RES");
                } else {
                    WiSunBackboneLinkPhyInterceptor::GetInstance().InjectRxData(_recv_buffer, ret);
                }
            } else {
                tr_error("Received data from unkown downlink host. Ignoring.");
            }
        }
    }
}
