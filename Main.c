#include <stdio.h>
#include <stdlib.h>
#include "C:\\Users\\JP\\Desktop\\escuela\\NPCAP\\npcap-sdk-1.06\\Include\\pcap.h"
#include <pcap.h>
#define LINE_LEN 16
#define RUTA "C:\\Users\\JP\\Desktop\\escuela\\Redes\\Proyecto\\paquetes3.pcap"
#define RUTA1 "C:\\Users\\JP\\Desktop\\escuela\\Redes\\ProA\\ipD.pcap"
#define RUTA2 "C:\\Users\\JP\\Desktop\\escuela\\Redes\\ProA\\ipC.pcap"
#define RUTA3 "C:\\Users\\JP\\Desktop\\escuela\\Redes\\ProA\\ipA.pcap"
#define RUTA4 "C:\\Users\\JP\\Desktop\\escuela\\Redes\\ProA\\ipB.pcap"
#define 	PCAP_OPENFLAG_PROMISCUOUS   1
#define 	PCAP_SRC_FILE   2
#define 	PCAP_BUF_SIZE   1024
//interfaz 3
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

void dispatcher_handlerARP(u_char *, const struct pcap_pkthdr *, const u_char *);
void dispatcher_handlerIP(u_char *, const struct pcap_pkthdr *, const u_char *);
void dispatcher_handlerIEEE(u_char *, const struct pcap_pkthdr *, const u_char *);
void tipoI(unsigned char, unsigned char, int);
void tipoS(unsigned char, unsigned char, int);
void tipoU(unsigned char);
void printfBin(unsigned char);
int arp();
int arpA();
int ip();
int	ipA();
int ieee();
void menuFiltros();
void encabezado(u_char *, const struct pcap_pkthdr *, const u_char *);

typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ip_header{
	u_char ver_ihl; // Version (4 bits) + IP header length (4 bits)
	u_char tos; // Type of service
	u_short tlen; // Total length
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
	u_char ttl; // Time to live
	u_char proto; // Protocol
	u_short crc; // Header checksum
	ip_address saddr; // Source address
	ip_address daddr; // Destination address
	u_int op_pad; // Option + Padding
}ip_header;

/* ICMP header */
typedef struct icmp_header{
	u_char type; // ICMP type
	u_char code; // ICMP code
	u_short crc; // Checksum
}icmp_header;

/* IGMP header */
typedef struct igmp_header{
	u_char type; // IGMP type
	u_char rsv1; // Reserved
	u_short crc; // Checksum
	u_short rsv2; // Reserved
	u_short ngr; // #Group records (1 at least)
}igmp_header;

/* TCP header */
typedef struct tcp_header{
	u_short sport; // Source port
	u_short dport; // Destination port
	u_int sec_num; // Secuence number
	u_int ack_num; // Ack number
	u_char d_offset_rsv; // 4bit data offset + 4bit reserved
	u_char flags; // TCP flags
	u_short window; // Window
	u_short crc; //Checksum
	u_short upointer;
}tcp_header;

/* UDP header */
typedef struct udp_header{
	u_short sport; // Source port
	u_short dport; // Destination port
	u_short len; // Length
	u_short crc; // Checksum
}udp_header;

int filtro = 0,bIGMP=0,bICMP=0,bTCP=0,bUDP=0,tramas = 0, tramasRequeridas = 0; //Banderas y filtro
int nto=0,narp=0,nic=0,nig=0,ntc=0,nud=0;


int main(int argc, char **argv){
	int opcionv = 0, opciona=0, tipocaptura=0, ntramas=0;
	
	while(tipocaptura != 3){
    system("cls");
		printf("******* Analizador de tramas *******\n\n");
    printf("Bienvenido, seleccione una opcion:\n");
		printf("1)Archivo\n2)Vuelo\n3)Salir\n\n");
		scanf("%d", &tipocaptura);
		
		switch(tipocaptura){
			case 1:
				system("cls");
            puts("****----------------****");
	        	printf("Seleccione el tipo de protocolo:\n");
		        printf("   1)IEEE\n   2)ARP\n   3)IP\n   Otro) volver al menu inicial\n");
		        scanf("%d", &opciona);
		
		        switch (opciona){
			        case 1:
			            ieee();
			            break;
			        case 2:
			            arpA();
			            break;
			        case 3:
						ipA();
						break;    
			        default:
			            puts("Opcion no valida");
			            break;
			    }
        		break;
	        case 2:
	        	system("cls");
	        	printf("Seleccione el tipo de protocolo:\n");
		        printf("   1)ARP\n   2)IP\n");
		        scanf("%d", &opcionv);
		
		        switch (opcionv){
			        case 1:
			            arp();
			            break;
			        case 2:
			            ip();
			            break;
		
			        default:
			            puts("Opcion no valida");
			            break;
			        }
        		break;
		}
        puts("\n");
    }
    return 0;
}

//Analizador IEEE con archivo
int ieee(){
    
    pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];

   /* if(argc != 2){
        printf("usage: %s filename", argv[0]);
        return -1;
    }*/

    /* Create the source string according to the new WinPcap syntax */
    if ( pcap_createsrcstr( source,         // variable that will keep the source string
                            PCAP_SRC_FILE,  // we want to open a file
                            NULL,           // remote host
                            NULL,           // port on the remote host
                            RUTA, //argv[1],        // name of the file we want to open
                            errbuf          // error buffer
                            ) != 0)
    {
        fprintf(stderr,"\nError creating a source string\n");
        return -1;
    }
    
    /* Open the capture file */
    if ( (fp= (pcap_t *)pcap_open(source,         // name of the device
                        65536,          // portion of the packet to capture
                                        // 65536 guarantees that the whole packet will be captured on all the link layers
                         PCAP_OPENFLAG_PROMISCUOUS,     // promiscuous mode
                         1000,              // read timeout
                         NULL,              // authentication on the remote machine
                         errbuf         // error buffer
                         ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the file %s\n", source);
        return -1;
    }

    // read and dispatch packets until EOF is reached
    pcap_loop(fp, 0, dispatcher_handlerIEEE, NULL);

    return 0;
}

/*Dispatcher handler para IEEE*/
void dispatcher_handlerIEEE(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    u_int i=0;
    int ext, j; //Extendido / No extendido
    int tipo; // 0 = I; 1 = S; 2 = U;
    unsigned int T_L, aux; 
	unsigned char i_g;
	unsigned char c_r;
		
    /*
     * Unused variable
     */
    (VOID)temp1;
	printf("---------------------------------------- Analisis de la trama ---------------------------\n");
    /* print pkt timestamp and pkt len */
    printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);          
    
    /* Print the packet */
    for (i=1; (i < header->caplen + 1 ) ; i++)
    {
        printf("%.2x ", pkt_data[i-1]);
        if ( (i % LINE_LEN) == 0) printf("\n");
    }
    
    printf("\n\n");     
    
    printf("MAC Destino: ");
    for(j = 0; j<6; j++){
        printf("%.2x ", pkt_data[j]);
    }
    puts("");

    printf("MAC Origen: ");
    for(j = 6; j<12; j++){
        printf("%.2x ", pkt_data[j]);
    }
    puts("");
	
	T_L = (pkt_data[12]*256)+pkt_data[13];
	printf("Longitud/tipo:\n(%.2x %.2x)Hex = (%d)Dec\n", pkt_data[12], pkt_data[13], T_L);
    
    if(T_L <= 1500){
        i_g = pkt_data[14]&0x01;
        printf("\n");
        printf("DSAP: %i\n", i_g);

        c_r = pkt_data[15]&0x01;
        printf("\n");
        printf("SSAP: %i\n", c_r);  
        puts("");
        
        if(i_g==0)
            printf("el destinatario es un protocolo individual");
        else
            printf("el destinatario es un conjunto de protocolos");
        
        c_r = pkt_data[15]&0x01;
        printf("\n");
        
        if(c_r==0)
            printf("el mensaje es de comando");
        else
            printf("el mensaje es de respuesta");
        
        printf("\n");

        //Modo extendido o no extendido mas logitud del campo de control
        printf("campo de control: ");
        if(T_L<1500 && T_L>3)
        {
            printf("2 bytes, Extendido\n");
            ext = 1;
        }
        else if(T_L==3 || T_L < 3){
            printf("1 byte\n"); 
            ext = 0;
        }

		puts("");
        //chequeo de tipo de trama
        aux = pkt_data[16]&0x01; //mascara para el ultimo bit 
        if(aux == 0){
            tipo = 0;
            puts("Trama tipo I");
            tipoI(pkt_data[16], pkt_data[17], ext);
            
        }
        else{
            aux = pkt_data[16]&0x03;
            if(aux == 1){
                tipo = 1;
                puts("Trama tipo S");
                tipoS(pkt_data[16], pkt_data[17], ext);
            }
            else{ 
                tipo = 2;
                puts("Trama tipo U");
                tipoU(pkt_data[16]);
            }
        }

        printf("-----------------------------------------------------------------------------------------\n");

        printf("\n\n\n");     

    }
    else
        puts("Secuencia de Ethernet");
    
    return;
}

//Analizador ARP con archivo
int arpA(){
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];

    /* Create the source string according to the new WinPcap syntax */
    if ( pcap_createsrcstr( source,         // variable that will keep the source string
                            PCAP_SRC_FILE,  // we want to open a file
                            NULL,           // remote host
                            NULL,           // port on the remote host
                            RUTA1, //argv[1],        // name of the file we want to open
                            errbuf          // error buffer
                            ) != 0)
    {
        fprintf(stderr,"\nError creating a source string\n");
        return -1;
    }
    
    /* Open the capture file */
    if ( (fp= (pcap_t *)pcap_open(source,         // name of the device
                        65536,          // portion of the packet to capture
                                        // 65536 guarantees that the whole packet will be captured on all the link layers
                         PCAP_OPENFLAG_PROMISCUOUS,     // promiscuous mode
                         1000,              // read timeout
                         NULL,              // authentication on the remote machine
                         errbuf         // error buffer
                         ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the file %s\n", source);
        return -1;
    }

    // read and dispatch packets until EOF is reached
    pcap_loop(fp, 0, dispatcher_handlerARP, NULL);

    return 0;
}

/*Dispatcher handler para ARP*/
void dispatcher_handlerARP(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data){
    u_int i=0;
    printf("\n");
 	
    /* Print the packet */
    for (i=1; (i < header->caplen + 1 ) ; i++)
    {
        printf("%.2x ", pkt_data[i-1]);
        if ( (i % LINE_LEN) == 0) printf("\n");        
    }
    
	printf("\n=================== Analisis ARP =================\n");
	int j=0;
		nto=nto+1;
    //type
	unsigned short tipo = (pkt_data[12]*256)+pkt_data[13];
    if(tipo = 254)
    	printf("Tipo: %d   %02X %02X (trama ARP) \n",tipo,pkt_data[12],pkt_data[13]);
    
    //Hw type 
	printf("\nHardware Type:");
	unsigned short hw_type = (pkt_data[14]*256)+pkt_data[15];
	switch(hw_type){
		case 1: 
			printf("\tEthernet\t");
			break;
		case 6: 
			printf("\tIEEE 802 Networks\t");
			break;
		case 7: 
			printf("\tARCNET\t");
			break;
		case 15: 
			printf("\tFrame Relay\t");
			break;
		case 16: 
			printf("\tAsynchronous Transfer Mode (ATM)\t");
			break;
		case 17: 
			printf("\tHDLC\t");
			break;
		case 18: 
			printf("\tFibre Channel \t");
			break;
		case 19: 
			printf("\tAsynchronous Transfer Mode (ATM)\t");
			break;
		case 20: 
			printf("\tSerial line\t");
			break;
		default:
			printf("\tUndefined\t");
			break;
	}
	printf("%02X %02X \n\n",pkt_data[14],pkt_data[15]);
	
	//Protocol type
	printf("\tProtocol Type:\t");
	unsigned short p_type = (pkt_data[16]*256)+pkt_data[17];
		printf("%d\t", p_type);
		printf("%02X %02X \n\n",pkt_data[16],pkt_data[17]);
		
	//Hw address size
	printf("\tHardware address size:\t");
	printf("%02X \t\n\n",pkt_data[18]);
	//printf("%d \t", pkt_data[18]*256);
	
	//Protocol address lenght
	printf("\tProtocol address lenght:\t");
	printf("%02X \n\n",pkt_data[19]);
	
	
	//op code
	printf("Op code:");
	unsigned short op_code = (pkt_data[20]*256)+pkt_data[21];
	switch(op_code){
		case 1: 
			printf("\tARP request\t");
			break;
		case 2: 
			printf("\tARP reply\t");
			break;
		case 3: 
			printf("\tRARP request\t");
			break;
		case 4: 
			printf("\tRARP reply\t");
			break;
		default:
			break;
	}
	printf("%02X %02X \n\n",pkt_data[20], pkt_data[21]);
	
	//Sender hardware address
	printf("Sender hardware address:\t");
	for(j=22; j<28; j++)
		printf("%.2x ",pkt_data[j]);
		
	//Sender protocol address
	printf("\n\nSender protocol address:\t");
	for(j=28; j<32; j++)
		printf("%.2x ",pkt_data[j]);
	printf("\t%ld.%ld.%ld.%ld\n",(pkt_data[28]*256/256), (pkt_data[29]*256/256),(pkt_data[30]*256/256),(pkt_data[31]*256/256));				
		
	//Target hardware address
	printf("\n\nTarget hardware address:\t");
	for(j=32; j<38; j++)
		printf("%.2x ",pkt_data[j]);
		
	//Target protocol address
	printf("\n\nTarget protocol address:\t");
	for(j=38; j<42; j++)
		printf("%.2x ",pkt_data[j]);
	printf("\t%ld.%ld.%ld.%ld\n\n",(pkt_data[38]*256/256), (pkt_data[39]*256/256),(pkt_data[40]*256/256),(pkt_data[41]*256/256));
		narp=narp+1;
    printf("\n\n");     
    
}

//Analizador ARP al vuelo
int arp(){

    pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_dumper_t *dumpfile;
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Introduzca el numero de interfaz que desee capturar (1-%d):",i);
	scanf("%d", &inum);
	
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the device */
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	 dumpfile = pcap_dump_open(adhandle, "paquetes.pcap");

    if(dumpfile==NULL)
    {
        fprintf(stderr,"\nError opening output file\n");
        return -1;
    }
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	int tramas = 0;
	printf("\nCuantas tramas quieres capturar?\n");
	scanf("%d",&tramas);
	
	/* start the capture */
	pcap_loop(adhandle,tramas, dispatcher_handlerARP, (unsigned char *)dumpfile);
  printf("------------Estadisticas------------");
	printf("Tramas ARP:%d\n",narp);
	printf("Tramas ICMP:%d\n",nic);
	printf("Tramas IGMP:%d\n",nig);
	printf("Tramas TCP:%d\n",ntc);
	printf("Tramas UDP:%d\n",nud);
	printf("Tramas total:%d",nto);
	pcap_close(adhandle);
  return 0;
}

//Analizador IP al vuelo
int ip(){
    pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_dumper_t *dumpfile;
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Introduzca el numero de interfaz que desee capturar (1-%d):",i);
	scanf("%d", &inum);
	
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the device */
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	 dumpfile = pcap_dump_open(adhandle, "paquetes.pcap");

    if(dumpfile==NULL)
    {
        fprintf(stderr,"\nError opening output file\n");
        return -1;
    }
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
  int tramas = 0;
	printf("\nCuantas tramas quieres capturar?\n");
	scanf("%d",&tramas);
  menuFiltros();
  
	
	/* start the capture */
	pcap_loop(adhandle, tramas, dispatcher_handlerIP, (unsigned char *)dumpfile);
	bICMP = 0;
  	bIGMP = 0;
  	bTCP = 0;
  	bUDP = 0;
  printf("Tramas ARP:%d\n",narp);
	printf("Tramas ICMP:%d\n",nic);
	printf("Tramas IGMP:%d\n",nig);
	printf("Tramas TCP:%d\n",ntc);
	printf("Tramas UDP:%d\n",nud);
	printf("Tramas total:%d\n",nto);
	pcap_close(adhandle);

	puts("\n**Pulse cualquier tecla para continuar**\n");
  getch();
	return 0;
}

//Analizador IP con archivo
int ipA(){
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];

    /* Create the source string according to the new WinPcap syntax */
    if ( pcap_createsrcstr( source,         // variable that will keep the source string
                            PCAP_SRC_FILE,  // we want to open a file
                            NULL,           // remote host
                            NULL,           // port on the remote host
                            RUTA2, //argv[1],        // name of the file we want to open
                            errbuf          // error buffer
                            ) != 0)
    {
        fprintf(stderr,"\nError creating a source string\n");
        return -1;
    }
    
    /* Open the capture file */
    if ( (fp= (pcap_t *)pcap_open(source,         // name of the device
                        65536,          // portion of the packet to capture
                                        // 65536 guarantees that the whole packet will be captured on all the link layers
                         PCAP_OPENFLAG_PROMISCUOUS,     // promiscuous mode
                         1000,              // read timeout
                         NULL,              // authentication on the remote machine
                         errbuf         // error buffer
                         ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the file %s\n", source);
        return -1;
    }

    // read and dispatch packets until EOF is reached
    menuFiltros();
    pcap_loop(fp, 0, dispatcher_handlerIP, NULL);
    bICMP = 0;
    bIGMP = 0;
    bTCP = 0;
    bUDP = 0;
    puts("\n**Pulse cualquier tecla para continuar**\n");
    getch();
    
    return 0;
}

/* Packet Handler IP */
void dispatcher_handlerIP(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
   
	int i = 0;
	unsigned short tipo = (pkt_data[12]*256)+pkt_data[13];
	
	if (tipo==2048){
      nto=nto+1;
		//Impresion del paquete
    ip_header *ih;
		ih = (ip_header	 *) (pkt_data + 14); //length of ethernet header
		
		
		//Obtencion de Protocolo
		if(ih->proto==0x00){
			printf("Protocolo: Reservado\n");
		}else if(ih->proto==1 && bICMP == 1){
      nic=nic+1;
      encabezado(param,header,pkt_data);
			icmp_header *icmp;
			u_char ihl = ((ih->ver_ihl)&0x0f)*4;
			icmp = (icmp_header *) (pkt_data + 14+(ihl));
			printf("Protocolo: ICMP\n");
			if(icmp->type==0 && icmp->code==0){
				printf("\t- Tipo: Echo Reply\n");
				printf("\t- Codigo: 0 (Echo Reply)\n");
			}else if(icmp->type==3 && icmp->code==0){
				printf("\t- Tipo: Destination Unreachable\n");
				if(icmp->code==0){
					printf("\t- Codigo: 0 (Destination network unreachable)\n");
				}else if(icmp->code==1){
					printf("\t- Codigo: 1 (Destination host unreachable)\n");
				}else if(icmp->code==2){
					printf("\t- Codigo: 2 (Destination protocol unreachable)\n");
				}else if(icmp->code==3){
					printf("\t- Codigo: 3 (Destination port unreachable)\n");
				}else if(icmp->code==4){
					printf("\t- Codigo: 4 (Fragmentation needed and DF flag set)\n");
				}else if(icmp->code==5){
					printf("\t- Codigo: 5 (Source route failed)\n");
				}
			}else if(icmp->type==5){
				printf("\t- Tipo: Redirect Message\n");
				if(icmp->code==0){
					printf("\t- Codigo: 0 (Redirect datagram for the network)\n");
				}else if(icmp->code==1){
					printf("\t- Codigo: 1 (Redirect datagram for the type host)\n");
				}else if(icmp->code==2){
					printf("\t- Codigo: 2 (Redirect datagram for the Type of Service and Network)\n");
				}else if(icmp->code==3){
					printf("\t- Codigo: 3 (Redirect datagram for the Service and Host)\n");
				}
			}else if(icmp->type==8){
				printf("\t- Tipo: Echo Request\n");
				printf("\t- Codigo: 0 (Echo Request)\n");
			}else if(icmp->type==9){
				printf("\t- Tipo: Router Advertisement\n");
				printf("\t- Codigo: 0 (Use to discover the addresses of operational routers)\n");
			}else if(icmp->type==10){
				printf("\t- Tipo: Router Solicitation\n");
				printf("\t- Codigo: 0 (Use to discover the addresses of operational routers)\n");
			}else if(icmp->type==11){
				printf("\t- Tipo: Time Exceeded\n");
				if(icmp->code==0){
					printf("\t- Codigo: 0 (Time to live exceeded in transit)\n");
				}else if(icmp->code==1){
					printf("\t- Codigo: 1 (Fragment reassembly time exceeded)\n");
				}
			}else if(icmp->type==12){
				printf("\t- Tipo: Parameter Problem\n");
				if(icmp->code==0){
					printf("\t- Codigo: 0 (Pointer indicates error)\n");
				}else if(icmp->code==1){
					printf("\t- Codigo: 1 (Missing requiered option)\n");
				}else if(icmp->code==2){
					printf("\t- Codigo: 2 (Bad length)\n");
				}
			}else if(icmp->type==13){
				printf("\t- Tipo: Timestamp\n");
				printf("\t- Codigo: 0 (Used for time synchronization)\n");
			}else if(icmp->type==14){
				printf("\t- Tipo: Timestamp Reply\n");
				printf("\t- Codigo: 0 (Reply to Timestamp message)\n");
			}
			printf("\t- Checksum: %X\n",((icmp->crc&0xFF)<<8) | (icmp->crc>>8));
      printf("IP de Origen: %d.%d.%d.%d \n", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
		  printf("IP de Destinatario: %d.%d.%d.%d \n",ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
      printf("\n\n");
		}else if(ih->proto==0x02 && bIGMP == 1){
      nig=nig+1;
      encabezado(param,header,pkt_data);
			igmp_header *igmp;
			u_char ihl = ((ih->ver_ihl)&0x0f)*4;
			igmp = (igmp_header *) (pkt_data + 14+(ihl));
			printf("Protocolo: IGMP\n");
			u_short check = ((igmp->crc&0xFF)<<8) | (igmp->crc>>8);
			u_short rsv2 = ((igmp->rsv2&0xFF)<<8) | (igmp->rsv2>>8);
			u_short group = ((igmp->ngr&0xFF)<<8) | (igmp->ngr>>8);
			if(igmp->type==0x11){
				printf("\t- Tipo: Membership Query\n");
			}else if(igmp->type==0x12){
				printf("\t- Tipo: IGMPv1 (Membership Report)\n");
				printf("\t- Unused: %.2X\n",igmp->rsv1);
				printf("\t- Checksum: %.4X\n",check);
				printf("\t- Direccion de Grupo: %.4X %.4X",rsv2,group);
			}else if(igmp->type==0x16){
				printf("\t- Tipo: IGMPv2 (Membership Report)\n");
				printf("\t- Maximo Tiempo de Respuesta: %.2X\n",igmp->rsv1);
				printf("\t- Checksum: %.4X\n",check);
				printf("\t- Direccion de Grupo: %.4X %.4X",rsv2,group);
			}else if(igmp->type==0x22){
				printf("\t- Tipo: IGMPv3 (Membership Report)\n");
				printf("\t- Reservado: %.2X\n",igmp->rsv1);
				printf("\t- Checksum: %.4X\n",check);
				printf("\t- Reservado: %.4X\n",rsv2);
				printf("\t- Number of Group Records: %d (Hex= %.4X)\n",group,group);
				printf("\t\tGroup Record: \n");
				u_short record = pkt_data[46];
				u_short auxlen = pkt_data[47];
				u_short numsrc = pkt_data[48] | pkt_data[49];
				if(record==1){
					printf("\t\t\t-> Record Type: %.2X (MODE_IS_INCLUDE)\n",record);	
				}else if(record==2){
					printf("\t\t\t-> Record Type: %.2X (MODE_IS_EXCLUDE)\n",record);
				}else if(record==3){
					printf("\t\t\t-> Record Type: %.2X (Change_TO_INCLUDE_MODE)\n",record);
				}else if(record==4){
					printf("\t\t\t-> Record Type: %.2X (Change_TO_EXCLUDE_MODE)\n",record);
				}
				printf("\t\t\t-> Aux Data Len: %.2X\n",auxlen);
				printf("\t\t\t-> Number of sources: %.4X\n",numsrc);
				printf("\t\t\t-> Multicast Address: %d.%d.%d.%d\n",pkt_data[50],pkt_data[51],pkt_data[52],pkt_data[53]);
			}else if(igmp->type==0x17){
				printf("\t- Tipo: Leave Group");
			}
      printf("IP de Origen: %d.%d.%d.%d \n", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
		  printf("IP de Destinatario: %d.%d.%d.%d \n",ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
      printf("\n\n");
		}else if(ih->proto==0x03){
			printf("Protocolo: GGP\n");
		}else if(ih->proto==0x04){
			printf("Protocolo: IP\n");
		}else if(ih->proto==0x05){
			printf("Protocolo: ST\n");
		}else if(ih->proto==0x06 && bTCP == 1){
      ntc=ntc+1;
      encabezado(param,header,pkt_data);
			tcp_header *tcp;
			u_char ihl = ((ih->ver_ihl)&0x0f)*4;
			tcp = (tcp_header *) (pkt_data + 14 + (ihl));
			printf("Protocolo: TCP\n");
			u_short puerto_o = ((tcp->sport&0xFF)<<8) | (tcp->sport>>8);
			u_short puerto_d = ((tcp->dport&0xFF)<<8) | (tcp->dport>>8);
			u_int secuence = (((tcp->sec_num)&0xFF)<<24) | (((tcp->sec_num>>8)&0xFF)<<16) | (((tcp->sec_num>>16)&0xFF)<<8) | (tcp->sec_num>>24)&0xFF;
			u_int ack = (((tcp->ack_num)&0xFF)<<24) | (((tcp->ack_num>>8)&0xFF)<<16) | (((tcp->ack_num>>16)&0xFF)<<8) | (tcp->ack_num>>24)&0xFF;
			u_short offset = tcp->d_offset_rsv>>4;
			u_short reserv = (tcp->d_offset_rsv<<4)&0xF;
			u_short urg_act = ((tcp->upointer&0xFF)<<8) | (tcp->upointer>>8);
			u_short window = ((tcp->window&0xFF)<<8) | (tcp->window>>8);
			u_short check = ((tcp->crc&0xFF)<<8) | (tcp->crc>>8);
			printf("\t- Puerto de Origen: %d (Hex = %.4x)\n",puerto_o,puerto_o);
			printf("\t- Puerto de Destino: %d (Hex = %.4x)\n",puerto_d,puerto_d);
			printf("\t- Numero de Secuencia: %.8X\n",secuence);
			printf("\t- ACK: %.8X\n",ack);
			printf("\t- Offset: %X\n",offset);
			printf("\t- Reservado: %X\n",reserv);
			if(tcp->flags==0x01){
				printf("\t- Bandera encendida: FIN -------X\n");
			}else if(tcp->flags==0x02){
				printf("\t- Bandera encendida: SYN ------X-\n");
			}else if(tcp->flags==0x04){
				printf("\t- Bandera encendida: RST -----X--\n");
			}else if(tcp->flags==0x08){
				printf("\t- Bandera encendida: PSH ----X---\n");
			}else if(tcp->flags==0x10){
				printf("\t- Bandera encendida: ACK ---X----\n");
			}else if(tcp->flags==0x20){
				printf("\t- Bandera encendida: URG --X-----\n");
				printf("\t\tUrgent pointer: %X\n",urg_act);
			}else if(tcp->flags==0x40){
				printf("\t- Bandera encendida: ECE -X------\n");
			}else if(tcp->flags==0x80){
				printf("\t- Bandera encendida: CWR X-------\n");
			}
			printf("\t- Ventana: %.4X\n",window);
			printf("\t- Checksum: %.4X\n",check);
      printf("IP de Origen: %d.%d.%d.%d \n", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
		  printf("IP de Destinatario: %d.%d.%d.%d \n",ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
      printf("\n\n");
		}else if(ih->proto==0x07){
			printf("Protocolo: UCL\n");
		}else if(ih->proto==0x08){
			printf("Protocolo: EGP\n");
		}else if(ih->proto==0x09){
			printf("Protocolo: IGP\n");
		}else if(ih->proto==0xA){
			printf("Protocolo: BBN-RCC-MON\n");
		}else if(ih->proto==0xB){
			printf("Protocolo: NVP-II\n");
		}else if(ih->proto==0xC){
			printf("Protocolo: PUP\n");
		}else if(ih->proto==0xD){
			printf("Protocolo: ARGUS\n");
		}else if(ih->proto==0xE){
			printf("Protocolo: EMCON\n");
		}else if(ih->proto==0xF){
			printf("Protocolo: XNET\n");
		}else if(ih->proto==0x10){
			printf("Protocolo: CHAOS\n");
		}else if(ih->proto==0x11 && bUDP == 1){
      nud=nud+1;
      encabezado(param,header,pkt_data);
			udp_header *udp;
			u_char ihl = ((ih->ver_ihl)&0x0f)*4;
			udp = (udp_header *) (pkt_data + 14 + (ihl));
			printf("Protocolo: UDP\n");
			u_short puerto_o = ((udp->sport&0xFF)<<8) | (udp->sport>>8);
			u_short puerto_d = ((udp->dport&0xFF)<<8) | (udp->dport>>8);
			u_short longitud = ((udp->len&0xFF)<<8) | (udp->len>>8);
			u_short crc = ((udp->crc&0xFF)<<8) | (udp->crc>>8);
			printf("\t- Puerto de Origen: %d (Hex = %.4X)\n",puerto_o,puerto_o);
			printf("\t- Puerto de Destino: %d (Hex = %.4X)\n",puerto_d,puerto_d);
			printf("\t- Longitud del UDP: %d (Hex = %.4X)\n",longitud,longitud);
			printf("\t- Checksum: %.4X\n",crc);
      printf("IP de Origen: %d.%d.%d.%d \n", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
		  printf("IP de Destinatario: %d.%d.%d.%d \n",ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
      printf("\n\n");
		}else if(ih->proto==0x12){
			printf("Protocolo: MUX\n");
		}else if(ih->proto==0x13){
			printf("Protocolo: DCN-MEAS\n");
		}else if(ih->proto==0x14){
			printf("Protocolo: HMP\n");
		}else if(ih->proto==0x15){
			printf("Protocolo: PRM\n");
		}else if(ih->proto==0x16){
			printf("Protocolo: XNS-IDP\n");
		}else if(ih->proto==0x17){
			printf("Protocolo: TRUNK-1\n");
		}else if(ih->proto==0x18){
			printf("Protocolo: TRUNK-2\n");
		}else if(ih->proto==0x19){
			printf("Protocolo: LEAF-1\n");
		}else if(ih->proto==0x1A){
			printf("Protocolo: LEAF-2\n");
		}else if(ih->proto==0x1B){
			printf("Protocolo: RDP\n");
		}else if(ih->proto==0x1C){
			printf("Protocolo: IRTP\n");
		}else if(ih->proto==0x1D){
			printf("Protocolo: ISO-TP4\n");
		}else if(ih->proto==0x1E){
			printf("Protocolo: NETBLT\n");
		}else if(ih->proto==0x1F){
			printf("Protocolo: MFE-NSP\n");
		}else if(ih->proto==0x20){
			printf("Protocolo: MERIT-INP\n");
		}else if(ih->proto==0x21){
			printf("Protocolo: SEP\n");
		}else if(ih->proto==0x22){
			printf("Protocolo: 3PC\n");
		}else if(ih->proto==0x23){
			printf("Protocolo: IDPR\n");
		}else if(ih->proto==0x24){
			printf("Protocolo: XTP\n");
		}else if(ih->proto==0x25){
			printf("Protocolo: DDP\n");
		}
				
		

    
	}
}

void encabezado(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){
	int i;
  ip_header *ih;
	ih = (ip_header	 *) (pkt_data + 14); //length of ethernet header

  printf("\tPaquete:\n\n");
		for (i=1; (i < header->caplen + 1 ) ; i++)
    		{
    			printf("%.2x ", pkt_data[i-1]);
        		if ( (i % LINE_LEN) == 0) printf("\n");
    		}
    	printf("\n\n\tAnalisis del Paquete IP..\n\n");
    	//Asignacion del inicio del paquete
		
		
		//Obtencion de la version
		if((ih->ver_ihl&0xf0)==0x40){
			printf("Version: IPv4\n");
		}else if((ih->ver_ihl&0xf0)==0x60){
			printf("Version: IPv6\n");
		}
		
		//Obtencion del IHL
		printf("IHL: %.2X\n",ih->ver_ihl&0x0f);
		
		//Obtencion de la clase
		if((ih->tos&0xE0)==0x00){
			printf("Class: Routine\n");
		}else if((ih->tos&0xE0)==0x10){
			printf("Class: Priority\n");
		}else if((ih->tos&0xE0)==0x20){
			printf("Class: Immediate\n");
		}else if((ih->tos&0xE0)==0x30){
			printf("Class: Flash\n");
		}else if((ih->tos&0xE0)==0x40){
			printf("Class: Flash Override\n");
		}else if((ih->tos&0xE0)==0x50){
			printf("Class: CRITIC/ECP\n");
		}else if((ih->tos&0xE0)==0x60){
			printf("Class: Internetwork Control\n");
		}else if((ih->tos&0xE0)==0x70){
			printf("Class: Network Control\n");
		}
		
		//Obtencion del ECN
		if((ih->tos&0x03)==0x00){
			printf("ECN: Sin capacidad\n");
		}else if((ih->tos&0x03)==0x01){
			printf("ECN: Capacidad de transporte (0)\n");
		}else if((ih->tos&0x03)==0x02){
			printf("ECN: Capacidad de transporte (1)\n");
		}else if((ih->tos&0x03)==0x03){
			printf("ECN: Congestion encontrada\n");
		}
		
		//Obtencion de la longitud
		u_short tamano = ((ih->tlen&0xFF)<<8) | (ih->tlen>>8);
		printf("Tamano: %d (Hex = %.4X)\n",tamano,tamano);
		
		//Obtencion de la identificacion
		u_short id = ((ih->identification&0xFF)<<8) | (ih->identification>>8);
		printf("ID: %d (Hex = %.4X)\n",id,id);
		
		//Obtencion de Banderas
		u_short bandera = ((ih->flags_fo&0xFF)<<8) | (ih->flags_fo>>8);
		if((bandera&0xE000)==0x2000){
			printf("Bandera: --X More activa\n");
		}else if((bandera&0xE000)==0x4000){
			printf("Bandera: -X- No fragmentar activa\n");
		}else{
			printf("No hay banderas encendidas\n");
		}
		
		//Obtencion del offset
		printf("Offset: %d\n",bandera&0x1FFF);
		
		//Obtencion del TTL
		printf("TTL: %d (Hex = %.2X)\n",ih->ttl,ih->ttl);
		
	    //Obtencion del Checksum
		u_short check = ((ih->crc&0xFF)<<8) | (ih->crc>>8);
		printf("Checksum: %.4X\n",check);
    return;
}

void tipoI(unsigned char pkt_dataA, unsigned char pkt_dataB, int ext){
    unsigned char aux;
    if(ext){
        aux = ((pkt_dataA)>>1)&0x127;
        printf("Numero de secuencia de envio: %.2x\n", aux);
        aux = ((pkt_dataB)>>1)&0x127;
        printf("Numero de secuencia de recibo: %.2x\n", aux);
        aux = pkt_dataB&0x01;
        printf("P/F: %.1x\n", aux);
    }
    else{
        aux = ((pkt_dataA)>>5)&0x07;
        printf("Numero de secuencia de envio: %.2x\n", aux);
        aux = ((pkt_dataA)>>1)&0x07;
        printf("Numero de secuencia de recibo: %.2x\n", aux);
        aux = pkt_dataB>>4&0x01;
        printf("P/F: %.1x\n", aux);
    }
}

void tipoS(unsigned char pkt_dataA, unsigned char pkt_dataB, int ext){
    unsigned char aux;
    if(ext){
        aux = (pkt_dataA&0x01>>2)&0x03;
        printf("SS: %.2x\n", aux);
        switch (aux)
        {
        case 0x00:
            puts("listo para recibir");
            break;
        case 0x01:
            puts("Rechazo");
            break;
        case 0x02:
            puts("Receptor no listo para recibir");
            break;
        case 0x03:
            puts("Rechazo Selectivo");
            break;
        
        default:
            break;
        }
        aux = (pkt_dataB>>1)&0x127;
        printf("Numero de acuse: %.2x\n", aux);
    }
    else{
        aux = (pkt_dataA>>2)&0x03;
        printf("SS: %.2x\n", aux);
        switch (aux)
        {
        case 0x00:
            puts("listo para recibir");
            break;
        case 0x01:
            puts("Rechazo");
            break;
        case 0x02:
            puts("Receptor no listo para recibir");
            break;
        case 0x03:
            puts("Rechazo Selectivo");
            break;
        
        default:
            break;
        }
        aux = (pkt_dataA>>5)&0x03;
        printf("Numero de acuse: %.2x\n", aux);
    }
}

void tipoU(unsigned char pkt_dataA){
    unsigned char aux1, aux2;
    int i;
    aux1 = (pkt_dataA>>2)&0x03;  //Ultimos 2 bits
    aux2 = (pkt_dataA>>5)&0x07; //Ultimos 3 bits
    printf("Secuencia de 5 bits: ");
    for(i = 0; i<3; i++){
        if(aux2&0x01)
            printf("1 ");
        else    
            printf("0 ");
        aux2 = aux2>>1;
    }

    for(i = 0; i<2; i++){
        if(aux1&0x01)
            printf("1 ");
        else    
            printf("0 ");
        aux1 = aux1>>1;
    }
    puts("");
    aux1= pkt_dataA>>3&0x01;
    printf("P/F: %.1x\n", aux1);
}

void menuFiltros(){
  puts("\nDesea aplicar algun filtro?\n");
  puts("Filtros :\n");
  puts("1) IGMP\n2) ICMP\n3) TCP\n4) UDP\n5) Incluir todos\n");
  scanf("%d",&filtro);

  bIGMP = 0;
  bICMP = 0;
  bTCP = 0;
  bUDP = 0;
    
  switch(filtro){
    case 1:{
      bIGMP = 1;
      break;
    }
    case 2:{
      bICMP = 1;
      break;
    }
    case 3:{
      bTCP = 1;
      break;
    }
    case 4:{
      bUDP = 1;
      break;
    }
    default:
      bIGMP = 1;
      bICMP = 1;
      bTCP = 1;
      bUDP = 1;
      break;
  }
  return ;
}
