#define HAVE_REMOTE
#include<stdio.h>
#include<pcap.h>

#define LINE_LEN 16

int main(int argc, char** argv) {
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i = 0;
	int res;
	
	if(argc != 2) {
		printf("useage: %s filename", argv[0]);
		return -1;
	}
	
	/* 根据新WinPcap语法创建一个源字符串 */
	if(pcap_createsrcstr(
		source, 		// 源字符串
		PCAP_SRC_FILE,  // 我们要打开的源文件
		NULL, 			// 远程主机
		NULL, 			// 远程主端口
		argv[1], 		// 我们要打开的文件名
		errbuf			// 错误缓冲区
	) != 0) {
 		fprintf(stderr, "\nError creating a source sring\n");
		 return -1;	
 	}
 	
 	/* 打开捕获文件 */
	if((fp = pcap_open(
	 	source, 		// 设备名
	 	65536, 
		// 65536保证能捕获到不用数据链路层上的每一个数据包的全部内容
	 	PCAP_OPENFLAG_PROMISCUOUS, // 混杂模式
	 	1000, 			// 读取超时时间
	 	NULL, 			// 远程主机验证
	 	errbuf 			// 错误缓冲池
 	)) == NULL) {
	 	fprintf(stderr, "\nUnable to open the file %s.\n", source);
		 return -1;
 	}
 	
 	/* 从文件获取数据包 */
	while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
		/* 打印pkt时间戳和pkt长度 */
		printf("%ld:%ld (%u)\n", header->ts.tv_sec, header->ts.tv_usec,
			header->len);
		
		/* 打印数据包 */
		for(i = 1; (i < header->caplen + 1); i++) {
			printf("%.2x ", pkt_data[i - 1]);
			if(i % LINE_LEN == 0) {
				printf("\n");
			}
		} 
		
		printf("\n\n");
	}
	
	if(res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
	}
	
	return 0;	
}
