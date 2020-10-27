#pragma once

#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
	Ip      dip_;
	Ip      sip_;

	Ip      dmac() { return dip_; }
	Ip      smac() { return sip_; }

};
//typedef EthHdr *PEthHdr;
#pragma pack(pop)
