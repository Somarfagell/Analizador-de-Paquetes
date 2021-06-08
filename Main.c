#include <stdio.h>
#include <stdlib.h>
#include "C:\\Users\\JP\\Desktop\\escuela\\NPCAP\\npcap-sdk-1.06\\Include\\pcap.h"
#include <pcap.h>
#define LINE_LEN 16
#define RUTA "C:\\Users\\JP\\Desktop\\escuela\\Redes\\Proyecto\\paquetes3.pcap"
#define 	PCAP_OPENFLAG_PROMISCUOUS   1
#define 	PCAP_SRC_FILE   2
#define 	PCAP_BUF_SIZE   1024
//interfaz 3
#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

//Version de prueba 1
void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
void tipoI(unsigned char, unsigned char, int);
void tipoS(unsigned char, unsigned char, int);
void tipoU(unsigned char);
void printfBin(unsigned char);
void arp();
void ip();
void ieee();
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void packet_handlera(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

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


int main(int argc, char **argv)
{
	
	int opcion = 0;
    while(opcion != 4){
        printf("Interfaz de inicio para el analizador de tramas\n");
        printf("1)Analizador IEEE\n2)ARP\n3)IP\n4)Salir\n");
        scanf("%d", &opcion);

        switch (opcion)
        {
        case 1:
            ieee();
            break;

        case 2:
            arp();
            break;

        case 3:
            ip();
            break;

        case 4:
            exit(0);
            break;

        default:
            puts("Opcion no valida");
            break;
        }
        puts("\n");
    }

    return 0;
}


//Seccion de analizador ieee
void ieee(){
    
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
    pcap_loop(fp, 0, dispatcher_handler, NULL);

    return;
}

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
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

//inicio de arp
void arp(){

    pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
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
	
	printf("Enter the interface number (1-%d):",i);
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
	
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	pcap_loop(adhandle, 1000, packet_handler, NULL);
	
	pcap_close(adhandle);
    return;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	/*
	 * unused parameters
	 */
	(VOID)(param);
	(VOID)(pkt_data);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	//ltime=localtime(&local_tv_sec);
	//strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	
	//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	
	int j = 0, tab = 1, bit = 1, aux;
	
	
	//Para convertir un hex de dos bytes a int (pkt_data[0]*256)+pkt_data[1];
	//Formateo de codigo
	
	aux = (pkt_data[12]*256) + pkt_data[13];
	if(aux == 2054){
		//Formato de trama a 16 bytes
		puts("\n------------------------------------------------");
		puts("Tipo: ARP");
		while(j<32){
		if(tab < 8)
		printf("%.2X ",pkt_data[j]);
		else{
			printf("%.2X ",pkt_data[j]);
			puts("");
			tab = 0;
			}   
			tab++;
			j+=1;
		}

		//Tipo de hardware
		aux = (pkt_data[14]*256) + pkt_data[15];
		printf("Tipo de hardware: ");
		switch (aux)
		{
		case 1:
			printf("%.2x Ethernet\n", aux);
			break;
		case 6:
			printf("%.2x IEEE 802 Networks\n", aux);
			break;
		case 7:
			printf("%.2x ARCTNET\n", aux);
			break;
		case 15:
			printf("%.2x Frame Relay\n", aux);
			break;
		default:
			puts("");
			break;
		}

		//Tipo de protocolo
		aux = (pkt_data[16]*256) + pkt_data[17];
		printf("Tipo de protocolo: ");
		switch (aux)
		{
		case 2048:
			printf("%.2x %.2x IPV4\n", pkt_data[16], pkt_data[17]);
			break;
		case 2054:
			printf("%.2x %.2x ARP\n", pkt_data[16], pkt_data[17]);
			break;
		case 2056:
			printf("%.2x %.2x Frame Relay ARP\n", pkt_data[16], pkt_data[17]);
			break;
		case 2058:
			printf("%.2x %.2x Point-to-Point Tunneling Protocol (PPTP)\n", pkt_data[16], pkt_data[17]);
			break;
		default:
			puts("");
			break;
		}

		//Tamaño de hardware
		printf("Tam de hardware: %d\n", pkt_data[18]);
		
		//Tamaño de protocolo
		printf("Tam de protocolo: %d\n", pkt_data[29]);

		//OP code
		
		aux = (pkt_data[20]*256) + pkt_data[21];
		printf("OP code: %d ",aux);
		switch (aux)
		{
		case 1:
			printf("ARP Request\n");
			break;
		case 2:
			printf("ARP REPLY\n");
			break;
		case 3:
			printf("ARP Request Reverse\n");
			break;
		case 4:
			printf("ARP Reply Reverse\n");
			break;
		default:
			puts("");
			break;
		}

		//Hardware addres
		printf("Direccion MAC de emisor: ");
		int ad = 0;
		while(ad<5){
			printf("%.2X:",pkt_data[22+ad]);
			ad+=1;
		}
		printf("%.2X",pkt_data[22+ad]);
		puts("");

		//IP address
		printf("Direccion IP de emisor: ");
		ad = 0;
		while(ad<3){
			printf("%d.",pkt_data[28+ad]);
			ad+=1;
		}
		printf("%d",pkt_data[28+ad]);
		puts("");
		
		//MAC destino:
		printf("Direccion MAC de receptor: ");
		ad = 0;
		while(ad<5){
			printf("%.2X:",pkt_data[32+ad]);
			ad+=1;
		}
		printf("%.2X",pkt_data[32+ad]);
		puts("");

		//MAC destino:
		printf("Direccion IP de receptor: ");
		ad = 0;
		while(ad<3){
			printf("%d.",pkt_data[38+ad]);
			ad+=1;
		}
		printf("%d",pkt_data[38+ad]);
		puts("\n------------------------------------------------\n\n");

	}
    
}


//seccion de ip
void ip(){
    pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
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
	
	printf("Enter the interface number (1-%d):",i);
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
	
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	pcap_loop(adhandle, 50, packet_handlera, NULL);
	
	pcap_close(adhandle);
    return;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handlera(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	/*
	 * unused parameters
	 */
	(VOID)(param);
	(VOID)(pkt_data);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	//ltime=localtime(&local_tv_sec);
	//strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	
	//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	
	unsigned short tipo = (pkt_data[12]*256)+pkt_data[13];
	if (tipo==2048){
		puts("*------------------------------------*");
		printf("Paquete IP..\n");
		ip_header *ih;
		u_int ip_len;
		/* retireve the position of the ip header */
		ih = (ip_header *) (pkt_data + 14); //length of ethernet header
		
		//Version
		printf("Version: %.2x  ",(ih->ver_ihl)&0xf0>>3);
		if(((ih->ver_ihl)&0xf0>>3) == 4)
			puts("IP Version 4");
		else 
			puts("IP Version 6");
		
		//IHL
		printf("IHL: %.2d \n",(ih->ver_ihl)&0x0f);
		printf("Tam: %d\n", ((ih->ver_ihl)&0x0f)*4);
		//Tipo de servicio
		//printf("DEBUG: %.2x \n",(ih->tos));
		printf("Tipo de servicio: %d  ",((ih->tos)>>5)&0x07);
		switch (((ih->tos)>>5)&0x07)
		{
		case 0:
			puts("Routine");
			break;
		case 1:
			puts("Priority");
			break;
		case 2:
			puts("Immediate");
			break;
		case 3:
			puts("Flash");
			break;
		case 4:
			puts("Flash Overdrive");
			break;
		case 5:
			puts("CRITIC/ECP");
			break;
		case 6:
			puts("Internetwork Control");
			break;	
		case 7:
			puts("Network Control");
			break;					
		default:
			puts("");
			break;
		}

		//ENC
		printf("ENC: %d  ",(ih->tos)&0x03);
		switch ((ih->tos)&0x03)
		{
		case 0:
			puts("Sin capacidad ECN");
			break;
		case 1:
			puts("Capacidad de transporte ENC(0)");
			break;
		case 2:
			puts("Capacidad de transporte ENC(1)");
			break;
		case 3:
			puts("Congestion encontrada");
			break;
					
		default:
			puts("");
			break;
		}
		
		//Banderas
		printf("Banderas: %d  ", (ih->flags_fo>>13)&0x07);
		switch ((ih->flags_fo>>13)&0x07)
		{
		case 0:
			puts("Fragmentacion permitida, Ultimo fragmento del paquete");
			break;
		case 1:
			puts("Fragmentacion permitida, a espera de mas fragmentos");
			break;
		case 2:
			puts("Paquete sin fragmentacion");
			break;
		default:
			break;
		}
		
		//Fragment offset
		printf("Offset de fragmento: %d\n", (ih->flags_fo)&0x1FFF);
		
		
		
		//ttl
		printf("TTL: %d\n", ih->ttl);
		//Protocolo
		printf("Protocolo: %d   ->   ", ih->proto);
		switch (ih->proto)
		{
		case 0:
			puts("RESERVADO");
			break;
		case 1:
			puts("ICMP");
			break;
		case 2:
			puts("IGMP");
			break;
		case 3:
			puts("GGP");
			break;
		case 4:
			puts("IP");
			break;
		case 5:
			puts("ST");
			break;
		case 6:
			puts("TCP");
			break;
		case 7:
			puts("UCL");
			break;
		case 8:
			puts("EGP");
			break;
		case 17:
			puts("UDP");
			break;
		default:
			break;
		}
		
		//checksum
		printf("Cheksum: %d\n", ih->crc);
		
		//options
		printf("Opciones: %.2x %.2x %.2x", ih->op_pad&0xFF000000>>24, ih->op_pad&0xFF0000>>26, ih->op_pad&0xFF00>>8, ih->op_pad&0xFF);
		

		puts("\n");
		/* print ip addresses and udp ports */
		printf("Source Address: %d.%d.%d.%d\n", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
		printf("Destination Address: %d.%d.%d.%d\n", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
		
		puts("\n\n*------------------------------------*\n\n");
	}
    
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
