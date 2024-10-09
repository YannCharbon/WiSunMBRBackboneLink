/**
 * @author Yann Charbon <yann.charbon@heig-vd.ch>
 * @copyright 2024
 */

#include "WiSunBackboneLinkPhyInterceptor.h"

#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "BBLI"

int WiSunBackboneLinkPhyInterceptor::_orig_phy_driver_id = -1;
phy_device_driver_s WiSunBackboneLinkPhyInterceptor::_orig_phy_driver;
phy_device_driver_s *WiSunBackboneLinkPhyInterceptor::_interceptor_driver = nullptr;

IWiSunBackboneLinkService *WiSunBackboneLinkPhyInterceptor::_service = nullptr;
WiSunBackboneLinkPhyInterceptor::FrameType WiSunBackboneLinkPhyInterceptor::_prev_frame_type = WiSunBackboneLinkPhyInterceptor::FrameType::OTHER;

WiSunBackboneLinkPhyInterceptor& WiSunBackboneLinkPhyInterceptor::GetInstance() {
    static WiSunBackboneLinkPhyInterceptor instance;
    return instance;
}

void WiSunBackboneLinkPhyInterceptor::SetBBLinkService(IWiSunBackboneLinkService* service) {
    _service = service;
}

int WiSunBackboneLinkPhyInterceptor::RegisterInterceptor() {
    int ret;
    tr_debug("Registering Wi-SUN Phy interceptor");

    int id = 0;
    arm_device_driver_list_s * ieee802154_arm_driver;
    while (((ieee802154_arm_driver = arm_net_phy_driver_pointer(id++)) == NULL || ieee802154_arm_driver->phy_driver->link_type != PHY_LINK_15_4_SUBGHZ_TYPE) && id < 256);
    if (id > 255 || !ieee802154_arm_driver) {
        tr_error("No IEEE 802.15.4 PHY driver found");
        return -1;
    }
    id--;

    while (!ieee802154_arm_driver->phy_driver->tx || !ieee802154_arm_driver->phy_driver->phy_rx_cb || !ieee802154_arm_driver->phy_driver->phy_tx_done_cb) {
        ThisThread::sleep_for(1s);
    }
    _orig_phy_driver_id = id;
    memcpy(&_orig_phy_driver, ieee802154_arm_driver->phy_driver, sizeof(_orig_phy_driver));
    _interceptor_driver = ieee802154_arm_driver->phy_driver;

    _InsertPhyInterceptor();

    tr_info("Successfully registered Wi-SUN Backbone link PHY interceptor");

    return 0;
}

void WiSunBackboneLinkPhyInterceptor::InjectRxData(uint8_t *data, uint16_t len) {
    // Don't call directly because the caller should be released as quickly as possible (might be an interrupt context)
    //mbed_event_queue()->call(_arm_net_phy_rx_fn_override, data, len, 0xff, 0, _orig_phy_driver_id);
    _arm_net_phy_rx_fn_override(data, len, 0xff, 0, _orig_phy_driver_id);
}

void WiSunBackboneLinkPhyInterceptor::_InsertPhyInterceptor() {
    /// @todo check for nullity
    // MAC --> PHY interception
    _interceptor_driver->tx = _start_cca_override;
    // PHY --> MAC interception
    _interceptor_driver->phy_rx_cb = _arm_net_phy_rx_fn_override;
    _interceptor_driver->phy_tx_done_cb = _arm_net_phy_tx_done_fn_override;
}

void WiSunBackboneLinkPhyInterceptor::_fake_ack_reception(uint8_t *fake_src_mac, uint8_t *dst_mac, uint8_t seq_number) {
    // Required because TCP link can be slower than the IEEE 802.15.4 ACK timeout

    if (fake_src_mac == NULL || dst_mac == NULL) {
        return;
    }

    uint8_t ack_frame[50];

    uint8_t *ptr = ack_frame;

    // Frame type: ACK, PAN ID Compression: 1, Information Element: Not present, Dest addr mode: Long, Frame version: 2015, Src addr mode: Long
    *ptr++ = 0x42;
    *ptr++ = 0xec;

    *ptr++ = seq_number;

    *ptr++ = dst_mac[7];
    *ptr++ = dst_mac[6];
    *ptr++ = dst_mac[5];
    *ptr++ = dst_mac[4];
    *ptr++ = dst_mac[3];
    *ptr++ = dst_mac[2];
    *ptr++ = dst_mac[1];
    *ptr++ = dst_mac[0];

    *ptr++ = fake_src_mac[7];
    *ptr++ = fake_src_mac[6];
    *ptr++ = fake_src_mac[5];
    *ptr++ = fake_src_mac[4];
    *ptr++ = fake_src_mac[3];
    *ptr++ = fake_src_mac[2];
    *ptr++ = fake_src_mac[1];
    *ptr++ = fake_src_mac[0];

    //tr_warn("Faking ACK");

    _arm_net_phy_rx_fn_override(ack_frame, ptr - ack_frame, 0xff, 0, _orig_phy_driver_id);
}

int8_t WiSunBackboneLinkPhyInterceptor::_start_cca_override(uint8_t *data_ptr, uint16_t data_length, uint8_t tx_handle, data_protocol_e data_protocol) {
    //tr_debug("Entering _start_cca_override");
    SendInterface send_iface = SendInterface::RF;
    uint8_t dst_mac[8];
    memset(dst_mac, 0, 8);
    bool broadcast = false;  // This variable is use to tell the service to only send the frame once. E.g. when FHSS is enabled, it is pointless to send a PAN Advert x times on x channels over the backhaul network
    FrameType current_frame_type = FrameType::OTHER;

    /*for (int i = 0; i < data_length; i++) {
        printf("%02X ", data_ptr[i]);
    }
    printf("\n");*/

    uint8_t *ptr = data_ptr;

    uint16_t control_field = *(uint16_t *)ptr;
    ptr += 2;


    uint8_t frame_type = ((control_field >> 0) & 0b111);

    uint8_t frame_version = ((control_field >> 12) & 0b11);
    if (frame_version != 0b10) {
        tr_debug("Frame is not 802.15.4-2015+ (%02X %02X %d %d)", data_ptr[0], data_ptr[1], control_field, frame_version);
        return -1;  // Frame is not IEEE 802.15.4-2015+
    }

    uint8_t ack_request = ((control_field >> 5) & 0b1);
    uint8_t pan_id_compression = ((control_field >> 6) & 0b1);
    uint8_t dst_addr_mode = ((control_field >> 10) & 0b11);
    uint8_t src_addr_mode = ((control_field >> 14) & 0b11);
    uint8_t ie_present = ((control_field >> 9) & 0b1);
    uint8_t seq_num_suppression = ((control_field >> 8) & 0b1);
    uint8_t security_enabled = ((control_field >> 3) & 0b1);

    uint8_t seq_number = 0;
    if (!seq_num_suppression) {
        seq_number = *ptr++;
    }

    if (dst_addr_mode != 0b00 && dst_addr_mode != 0b11) {
        // Not Wi-SUN complient
        send_iface = SendInterface::RF;
    } else {
        switch (dst_addr_mode) {
            case 0b00:
                // None (Broadcast)
                MBED_FALLTHROUGH;
            case 0b01:
                // Reserved
                send_iface = SendInterface::BOTH;
                break;
            default:
                break;
        }

        bool dst_pan_id_present = false;
        bool src_pan_id_present = false;

        if (dst_addr_mode == 0b0 && src_addr_mode == 0b0) {
            if (pan_id_compression == 1) {
                dst_pan_id_present = true;
            }
        } else if (dst_addr_mode > 0b1 && src_addr_mode == 0b0) {
            if (pan_id_compression == 0) {
                dst_pan_id_present = true;
            }
        } else if (dst_addr_mode == 0b0 && src_addr_mode > 0b1) {
            if (pan_id_compression == 0) {
                src_pan_id_present = true;
            }
        } else if (dst_addr_mode == 0b11 && src_addr_mode == 0b11) {
            if (pan_id_compression == 0) {
                dst_pan_id_present = true;
            }
        }

        if (dst_pan_id_present) {
            ptr += 2;
        }

        if (dst_addr_mode == 0b11) {
            dst_mac[7] = *ptr++;
            dst_mac[6] = *ptr++;
            dst_mac[5] = *ptr++;
            dst_mac[4] = *ptr++;
            dst_mac[3] = *ptr++;
            dst_mac[2] = *ptr++;
            dst_mac[1] = *ptr++;
            dst_mac[0] = *ptr++;
        }

        if (_service->CheckIfDstMACIsAnEndpoint(dst_mac) == true) {
            send_iface = SendInterface::BBLINK;
        }

        // Skip source address and PAN information
        if (src_pan_id_present) {
            ptr += 2;
        }

        if (src_addr_mode == 0b1) {
            ptr += 2;
        } else if (src_addr_mode == 0b11) {
            ptr += 8;
        }

        // Skip Auxiliary Security Header if present
        if (security_enabled) {
            uint8_t frame_counter_suppression = *ptr >> 5 & 0b1;
            uint8_t key_identifier_mode = *ptr >> 3 & 0b11;
            ptr++;

            if (!frame_counter_suppression) {
                ptr += 4;
            }
            switch(key_identifier_mode) {
                case 0x01:
                    ptr += 1;
                    break;
                case 0x02:
                    ptr += 5;
                    break;
                case 0x03:
                    ptr += 9;
                    break;
                default:
                    break;
            }
        }

        // Extract information element(s)
        if (ie_present) {

            uint8_t ie_len = *((uint16_t *)ptr) & 0b1111111;   // Length
            uint8_t ie_id = (*((uint16_t *)ptr) >> 7) & 0b11111111;   // Element ID (must be 0x2A for Wi-SUN)
            ptr += 2;

            if (ie_id == 0x2A) {    // WS-IE
                uint8_t ws_ie_sub_id = *ptr++;

                if (ws_ie_sub_id == 0x01) { // UTT-IE
                    switch (*ptr & 0b1111) {    // Frame type ID
                        case 0: /*PAN Advert*/
                            current_frame_type = FrameType::PA;
                        case 1: /*PAN Advert Solicit*/
                            current_frame_type = FrameType::PAS;
                        case 2: /*PAN Config*/
                            current_frame_type = FrameType::PC;
                        case 3: /*PAN Config Solicit*/
                            current_frame_type = FrameType::PCS;
                            broadcast = true;
                            break;
                        default:
                            current_frame_type = FrameType::OTHER;
                            break;
                    }
                }
            }
        }
    }

    bool new_frame = true;
    if (broadcast && current_frame_type != FrameType::OTHER && _prev_frame_type == current_frame_type) {
        new_frame = false;
    }
    _prev_frame_type = current_frame_type;


    //tr_debug("Forwarding to PHY");

    if (send_iface == SendInterface::RF) {
        return _orig_phy_driver.tx(data_ptr, data_length, tx_handle, data_protocol);
    } else if (send_iface == SendInterface::BBLINK) {
        _service->SendPHYToMatchingClientAsync(dst_mac, broadcast, new_frame, data_ptr, data_length);
        mbed_event_queue()->call(_arm_net_phy_tx_done_fn_override, _orig_phy_driver_id, tx_handle, PHY_LINK_CCA_PREPARE, 0, 0);
        mbed_event_queue()->call(_arm_net_phy_tx_done_fn_override, _orig_phy_driver_id, tx_handle, PHY_LINK_CCA_OK, 0, 0);
        mbed_event_queue()->call(_arm_net_phy_tx_done_fn_override, _orig_phy_driver_id, tx_handle, PHY_LINK_TX_SUCCESS, 0, 0);
        if (ack_request) {
            // This frame requires an acknowledge from the remote device
            mbed_event_queue()->call(_fake_ack_reception, dst_mac, _service->GetWiSunMacAddress(), seq_number);
        }
        return 0;
    } else {
        _orig_phy_driver.tx(data_ptr, data_length, tx_handle, data_protocol);
        /// @todo
        _service->SendPHYToMatchingClientAsync(NULL, broadcast, new_frame, data_ptr, data_length);
        return 0;
    }
}

int8_t WiSunBackboneLinkPhyInterceptor::_arm_net_phy_rx_fn_override(const uint8_t *data_ptr, uint16_t data_len, uint8_t link_quality, int8_t dbm, int8_t driver_id) {
    //tr_debug("Entering _arm_net_phy_rx_fn_override");

    //tr_info("Forwarding to MAC");
    return _orig_phy_driver.phy_rx_cb(data_ptr, data_len, link_quality, dbm, driver_id);
}

int8_t WiSunBackboneLinkPhyInterceptor::_arm_net_phy_tx_done_fn_override(int8_t driver_id, uint8_t tx_handle, phy_link_tx_status_e status, uint8_t cca_retry, uint8_t tx_retry) {
    //tr_debug("Entering _arm_net_phy_tx_done_fn_override");

    //tr_debug("Forwarding to MAC");
    return _orig_phy_driver.phy_tx_done_cb(driver_id, tx_handle, status, cca_retry, tx_retry);
}
