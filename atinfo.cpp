#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <libnet.h>
#include <string>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

struct EthArpPacket {
        EthHdr eth_;
        ArpHdr arp_;
};

int getAtkMac(Mac* atk_mac) {
	struct ifreq ifr;
	struct ifconf ifc;
	char buf[1024];
	int success = 0;

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) /* handle error*/
                return -1;

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) /* handle error */
                return -1;

	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

	for (; it != end; ++it) {
		strcpy(ifr.ifr_name, it->ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
			if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
				if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
					success = 1;
					break;
				}
			}
		}
		else /* handle error */
                	return -1;
    	}

	if (success)
	       	memcpy(atk_mac, ifr.ifr_hwaddr.sa_data, sizeof(Mac));
	else
		return -1;

	return 0;
}
int getAtkIp(Ip* atk_ip,char *dev){
	struct ifreq ifr;
	int s;
 
	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
 
	if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
        	return -1;
	else
		memcpy(atk_ip, ifr.ifr_addr.sa_data + 2, sizeof(Ip));
	close(s);

	return 0;
}
