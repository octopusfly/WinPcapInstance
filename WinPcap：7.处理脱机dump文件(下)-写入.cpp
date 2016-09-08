#define HAVE_REMOTE
#define WPCAP
#include<stdlib.h>
#include<stdio.h>
#include<pcap.h>

int main(int argc, char** argv) {
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	u_int inum, i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	printf("kdump: saves the network traffic to file using WinPcap"
		"kernel-level dump feature.\n");
	printf("\t Useage: %s [adapter] | dump_file max_size max_packs\n", argv[0]);
	printf("\t Where: max_size if the maxinum size that the dump file will"
		"reach (0 means no limit)\n");
	printf("\t Wherer max_packs is the maximum number of packets that will"
		"be saved (0 means no limit)\n\n");
	
	if(argc < 5) {
		/* 用户没有提供数据源。获取设备列表 */
		if(pcap_findalldevs(&alldevs, errbuf) == -1) {
			fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
			exit(1);
		} 
		
		/* 打印列表 */
		for(d = alldevs; d != NULL; d = d->next) {
			printf("%d.%s", ++i, d->name);
			if(d->description) {
				printf(" (%s)\n", d->description);
			} else {
				printf(" (No description available)\n");
			}
		} 
		
		if(i == 0) {
			printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
			return -1;
		}
		
		printf("Enter the interface number (1-%d):", i);
		scanf("%d", &inum);
		
		if(inum < 1 || inum > i) {
			printf("\nInterface numbe rout of range.\n");
			/* 释放列表 */
			pcap_freealldevs(alldevs);
			return -1; 
		} 
		
		/* 跳转到所选设备 */
		for(d = alldevs; i < inum - 1; d = d->next, i++);
		
		/* 打开设备 */
		if((fp = pcap_open_live(d->name, 100, 1, 2, errbuf)) == NULL) {
			fprintf(stderr, "\nError opening adapter\n");
			return -1;
		} 
		
		/* 释放设备列表 */
		pcap_freealldevs(alldevs); 
		
		/* 开始堆过程 */
		if(pcap_live_dump(fp, argv[1], atoi(argv[2]), atoi(argv[3])) == -1) {
			printf("Unable to start the dump, %s\n", pcap_geterr(fp));
			return -1;
		} 
	} else {
		/* 打开设备 */ 
		if((fp = pcap_open_live(argv[1], 100, 1, 20, errbuf)) == NULL) {
			fprintf(stderr, "\nError opening adapter\n");
			return -1;
		}
		
		/* 开始堆过程 */
		if(pcap_live_dump(fp, argv[2], atoi(argv[3]), atoi(argv[4])) == -1) {
			printf("Unable to start the dump, %s\n", pcap_geterr(fp));
			return -1;
		} 
	}
	
	/* 等待，直到堆过程完成，也就是当数据达到max_size或max_packs的时候 */
	pcap_live_dump_ended(fp, TRUE);
	
	/* 关闭适配器，这样可以将数据立刻输出到文件了 */
	pcap_close(fp);
	
	return 0; 
} 
