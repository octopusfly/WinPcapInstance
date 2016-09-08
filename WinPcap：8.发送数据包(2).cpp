#include<stdlib.h>
#include<stdio.h>

#define HAVE_REMOTE
#define WPCAP

#include<pcap.h>

void usage();

int main(int argc, char **argv) {
	pcap_t *indesc, *outdesc;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	FILE *capfile;
	int caplen, sync;
	u_int res;
	pcap_send_queue *squeue;
	struct pcap_pkthdr *pktheader;
	const u_char *pktdata;
	float cpu_time;
	u_int npacks = 0;
	
	/* 检查命令行参数的合法性 */
	if (argc <= 2 || argc >= 5) {
		usage();
		return -1;
	} 
	
	/* 获取捕获文件长度 */
	capfile = fopen(argv[1], "rb");
	if(!capfile) {
		printf("Capture file not found!\n");
		return -1;
	}
	
	fseek(capfile, 0, SEEK_END);
	caplen = ftell(capfile) - sizeof(struct pcap_file_header); 
	fclose(capfile);
	
	/* 检查时间戳是否合法 */
	if(argc == 4 && argv[3][0] == 's') {
		sync = TRUE;
	}  else {
		sync = FALSE;
	}
	
	/* 开始捕获 */
	/* 根据WinPcap的新语法创建一个源字符串 */
	if(pcap_createsrcstr(
		source,			// 源字符串
		PCAP_SRC_FILE,	// 我们要打开的文件 
		NULL,			// 远程主机 
		NULL,			// 远程主机端口 
		argv[1],		// 我们要打开的文件名 
		errbuf 	// 错误缓冲 
	) != 0) {
		fprintf(stderr, "\nError creating a source string\n");
		return -1;
	}
	
	printf("%s\n", source);
	/* 打开捕获文件 */
	if((indesc = pcap_open(source, 65536, PCAP_OPENFLAG_PROMISCUOUS,
		1000, NULL, errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to opent the file %s.\n", source);
		return -1;		
	}	
	
	/* 打开要输出的适配器 */
	if((outdesc = pcap_open(argv[2], 100, PCAP_OPENFLAG_PROMISCUOUS, 
		1000, NULL, errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to open adapter %s.\n", source);
		return -1;		
	} 
	
	/* 检查MAC类型 */
	if(pcap_datalink(indesc) != pcap_datalink(outdesc)) {
		printf("Warning: the datalink of the capture differs from"
			"one of the selected interface.\n");
		printf("Press a key to continue, or CTRL+C to stop.\n");
		getchar();
	} 
	
	/* 分配发送队列 */
	squeue = pcap_sendqueue_alloc(caplen); 
	
	/* 从文件中将数据包填充到发送队列 */
	while((res = pcap_next_ex(indesc, &pktheader, &pktdata)) == 1) {
		if(pcap_sendqueue_queue(squeue, pktheader, pktdata) == -1) {
			printf("Warning: packet buffer too small, not all the packets"
				"will be sent.\n");
			break;
		}
		npacks++; 
	} 
	
	if(res == -1) {
		printf("Corrupted input file.\n");
		pcap_sendqueue_destroy(squeue);
		return -1;
	}
	
	/* 发送队列 */
	printf("*"); 
	cpu_time = (float) clock();
	
	if((res = pcap_sendqueue_transmit(outdesc, squeue, sync)) 
		< squeue->len) {
		printf("An error occured sending the packets: %s."
			"Only %d bytes were sent.\n", pcap_geterr(outdesc), res);		
	}
	
	cpu_time = (clock() - cpu_time) / CLK_TCK;
	
	printf("\n\nElapsed time: %5.3f\n", cpu_time);
	printf("\nTotal packets generated = %d", npacks);
	printf("\nAverage packets per second = %d", 
		(int)((double) npacks / cpu_time));
	printf("\n");

	/* 释放发送队列 */
    pcap_sendqueue_destroy(squeue);

    /* 关闭输入文件 */
    pcap_close(indesc);

    /*
     * 释放输出适配器
     * IMPORTANT: 记得一定要关闭适配器，不然就不能保证
     * 所有的数据包都回被发送出去
     */
    pcap_close(outdesc);


    return 0;
}


void usage()
{
    printf("\nSendcap, sends a libpcap/tcpdump capture file to the net."
		"Copyright (C) 2002 Loris Degioanni.\n");
    printf("\nUsage:\n");
    printf("\t sendcap file_name adapter [s]\n");
    printf("\nParameters:\n");
    printf("\nfile_name: the name of the dump file that will be sent to the network\n");
    printf("\nadapter: the device to use. Use \"WinDump -D\" for a list of valid devices\n");
    printf("\ns: if present, forces the packets to be sent synchronously,"
		"i.e. respecting the timestamps in the dump file."
			"This option will work only under Windows NTx.\n\n");

    exit(0);
} 
