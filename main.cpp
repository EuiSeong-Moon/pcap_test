#include <iostream>
#include <pcap.h>
#include <cstring>
#include <cmath>
#include <cstdlib>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <cstdio>
using namespace std;
class Eths
{
public:
    uint8_t destination[6];
    uint8_t source[6];
    uint16_t eth_type;
};

class IPs
{
public:
    uint8_t header;
    uint8_t typeservice;
    uint16_t total;
    uint16_t skip[2];
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t destination;
    uint32_t source;
};

class Tcps
{
public:
    uint16_t source;       //const u_char *packet;		/* The actual packet */

    uint16_t destination;
    uint16_t sequence[2];
    uint16_t acknowledgement[2];
    uint8_t offset;
    uint8_t skip;
    uint16_t windows;
};


int main(int argc,char** argv)
{
    char timestr[16];
    struct tm *ltime;
    time_t local_tv_sec;
    int res;
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression */ //23번포트면 텔렛 80프토면 웹통신만 잡겟다는의미이다.
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */

    dev=argv[1];
    /* Define the device */
    // dev=argv[1];
    while(1)
    {
        /* The actual packet */

        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);//피캣오픈픈
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return(2);
        }
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }


        while(1)
        {
            char* buf;
            const u_char *packet;
            Eths* eths;
            IPs* ips;
            Tcps* tcps;
            while((res = pcap_next_ex(handle, &header,&packet)) >= 0){

                if(res == 0)
                    /* Timeout elapsed */
                    continue;


                //  printf("Packet infromation len : %d\n",header->len);

                if(packet!=NULL)
                {
                    eths=(Eths*)packet;
                    int datastart=14;

                    if(eths->eth_type==8)
                    {
                        ips=(IPs*)(packet+14);
                        uint8_t a=(ips->header)&0x0F;

                        int ipsize=4*a;
                        tcps=(Tcps*)(packet+ipsize+14);



                        datastart+=ipsize;


                        if(ips->protocol==0x06)
                        {

                            if(ntohs(tcps->source)==80 || ntohs(tcps->destination)==80)
                            {

                                cout<<"Eth destination :";
                                for(int i=0;i<6;i++)
                                    printf("%02x ",eths->destination[i]);
                                cout<<endl<<"Eth source :";
                                for(int i=0;i<6;i++)
                                    printf("%02x ",eths->source[i]);
                                cout<<endl;


                                cout<<"IP destination :";

                                buf=(char*)malloc(32);

                                inet_ntop(AF_INET,&ips->destination,buf,32);
                                printf("%s.",buf);
                                free(buf);

                                cout<<endl<<"IP Soure :";

                                buf=(char*)malloc(32);
                                inet_ntop(AF_INET,&ips->source,buf,32);
                                printf("%s.\n",buf);
                                free(buf);




                                uint8_t av=(tcps->offset)>>4;

                                av=av&0x0F;

                                int tcpsize=av*4;

                                datastart+=tcpsize;
                                buf=(char*)malloc(16);
                                inet_ntop(AF_INET,&tcps->source,buf,16);
                                printf("TCP source port : %d \n",ntohs(tcps->source));
                                free(buf);
                                buf=(char*)malloc(16);
                                inet_ntop(AF_INET,&tcps->destination,buf,16);

                                printf("TCP destination port : %d\n",ntohs(tcps->destination));
                                free(buf);

                                int datasizes=ntohs(ips->total);
                                printf("totla size : %d\n",datasizes);
                                printf("ipsize : %d\n",ipsize);
                                printf("tcpsize: %d\n",tcpsize);

                                datasizes=datasizes-ipsize-tcpsize;
                                if(datasizes<0 ||datasizes>header->len)
                                    datasizes=0;
                                printf("packet size : %d\n",header->len);
                                packet+=ipsize+tcpsize+13;
                                printf("data size : %d\n",datasizes);
                                for(int i=0;i<datasizes;i++)
                                {
                                    if(isprint(packet[i]))
                                        printf("%c",packet[i]);

                                    else
                                        printf(".");
                                }
                                // printf("%s",packet);
                                cout<<endl<<"---------------------------"<<endl;

                            }

                        }
                    }
                    break;
                }



            }

            if(res == -1){
                printf("Error reading the packets: %s\n", pcap_geterr(handle));
                return -1;

            }
        }       //패킷의 길이와 헤더정보가 넘어오고 pcap_next의 리턴 값이 바로 패킷이다 이더넷부터 쭉쭉 다있는 것 이 것이용 6바이트 6바이트출력해서 값얻어냄 분석시작
        //0x08로 뒤에 얹혀지는게 ip인거알아내면 또 읽어들여서 뒤에 바이트가지고, 분석 그다음 또 프로토콜로 다음올라가는거 확인 데이터부분은 앞의 10byte만출력
        //pcap_next는 타임아웃인지 못받은건지 알 수 없다 다 null만나옴 때문에 pcap_next_exe이걸 사용하면 타임아웃인지 아님 fail로못받은건지 오류의원인을 알수있다.
        /* Print its length */


    }

    pcap_close(handle);

    return(0);
}
