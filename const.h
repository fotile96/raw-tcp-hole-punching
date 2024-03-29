#pragma once

#define ENV_TCP_OPPONENT_ADDR "WEBSOCAT_CLIENT"
#define ENV_TCP_LOCAL_ADDR "PUNCH_TCP_LOCAL_ADDR"
#define ENV_UDP_LISTEN_ADDR "PUNCH_UDP_LISTEN_ADDR"
#define ENV_UDP_FORWARD_ADDR "PUNCH_UDP_FORWARD_ADDR"
#define ENV_RAW_LISTEN_DEV "RAW_LISTEN_DEV"
#define MAGIC_URGENT_POINTER 0x2333
#define MAGIC_URGENT_POINTER_PCAP_RULE "tcp[18:2] = 0x2333"

//#define SNIFF_SN_PCAP_RULE "tcp[tcpflags] == tcp-ack and ip[5] & 0xf == 0"
#define SNIFF_SN_PCAP_RULE "tcp[13] & 24 != 0 and ip[5] & 0xf == 0 and ip[2:2] <= 100"