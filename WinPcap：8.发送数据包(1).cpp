/*
	\Device\NPF_{27F25E26-24CC-4ED8-91DA-A70227A214A9}
 */

#include<stdlib.h>
#include<stdio.h>
#define HAVE_REMOTE
#include<pcap.h>

int main(int argc, char** argv) {
	pcap_t *fp;
	char errbuf[PCAP_BUF_SIZE];
	u_char packet[100];
	int i;
	
	/* 检查命令行参数的合法性 */
	if (argc != 2) {
		printf("Usage: %s interface (e.g. 'rpcap://eth0')", argv[0]);
		return -1;
	} 
	
	/* 打开输出设备 */
	if((fp = pcap_open(
		argv[1],			// 设备名 
		100,			// 要捕获的部分(只捕获前100字节) 
		PCAP_OPENFLAG_PROMISCUOUS, // 混杂模式 
		1000,			// 读超时时间 
		NULL, 			// 远程机器验证 
		errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to opent the adapter." 
			" %s is not supported by WinPcap.\n", argv[1]);
		return -1; 
	} 
	
	/* 假设在以太网上，设置MAC的目的地址为 1:1:1:1:1:1 */
	packet[0] = 1;
	packet[1] = 1;
	packet[2] = 1;
	packet[3] = 1;
	packet[4] = 1;
	packet[5] = 1;
	
	/* 设置MAC源地址为 2:2:2:2:2:2:2 */
	packet[6] = 2;
	packet[7] = 2;
	packet[8] = 2;
	packet[9] = 2;
	packet[10] = 2;
	packet[11] = 2; 
	
	/* 补充剩下的内容 */
	for(i = 12; i < 100; i++) {
		packet[i] = i % 256;
	} 
	
	/* 发送数据包 */
	if(pcap_sendpacket(fp, packet, 100 /* size */) != 0) {
		fprintf(stderr, "\nError sending the packet: %s\n", 
			pcap_geterr(fp));
		return -1;
	} 
	
	return 0;	 
} 
