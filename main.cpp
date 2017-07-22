#include <iostream>
#include <pcap.h>
#include <cstring>
#include <cmath>
#include <cstdlib>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
using namespace std;
class Eths
{
public:
    uint8_t destination[6];
    uint8_t source[6];
    uint16_t eth_type;
};
/*    void print(void)
    {
        printf("eth.dmac ");
        for(int i=0;i<6;i++)
            printf(": %02x",*(destination+i));
        cout<<endl;
        printf("eth.smac ");
        for(int i=0;i<6;i++)
            printf(": %02x",*(source+i));
        cout<<endl;
    }
};*/

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
/*    const unsigned char* pickip;

    void print(void)
    {
        printf("ip destination ");
        for(int i=0;i<4;i++)
            printf(": %d. ",*(destination+i));
        cout<<endl;
        printf("ip source ");
        for(int i=0;i<4;i++)
            printf(": %d. ",*(source+i));
        cout<<endl;
    }
};*/
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
/*
    void print(void)
    {
        printf("tcp destination ");
        // for(int i=0;i<2;i++)
        num1=pow(2,4);
        num1*=*(destination);
        num2=*(destination+1);
        printf(": %d",num1+num2);
        num4=num1+num2;
        cout<<endl;
        printf("tcp source ");
        //  for(int i=0;i<2;i++)
        num1=pow(2,4);
        num1*=*(source);
        num2=*(source+1);
        printf(": %d",num1+num2);
        cout<<endl;
        num3=num1+num2;
    }
};*/

/*void test (const u_char *packets,bpf_u_int32 lens)
{
    if(packets!=NULL)
    {
        Eths* eths=new Eths;
        IPs* ips=new IPs;
        Tcps* tcps=new Tcps;
        //strncpy(eths->destination,packets,6);
        eths->destination=packets;
        eths->source=(packets+=6);
        eths->pickip=(packets+=6);


        eths->print();
        if((*(eths->pickip))==128)
            cout<<"dd";
        if((*(eths->pickip))==8 && (*(eths->pickip+1)==0))
        {
            ips->destination=(packets+=18);
            ips->source=(packets-=4);
            ips->pickip=(packets-=3);
            ips->print();
            if(*(ips->pickip)==6)
            {
                tcps->source=(packets+=11);
                tcps->destination=(packets+=2);
                tcps->print();
                packets+=20;
                int i=0;
                // if(tcps->num3==80 || tcps->num4==80)
                // {

                if(lens-53>0)
                {
                    printf("DATA \n");
                    printf("%s",packets);

                    i=1;
                }
                //}
                if(i==0)
                    printf("No DATA \n");
                cout<<endl;
            }
            else
                cout<<"don't use tcp"<<endl;
        }
        else
        {
            cout<<"don't use ip "<<endl;
        }
        cout<< "------------------------------------------------------------"<<endl<<endl;
        delete eths;
        delete ips;
        delete tcps;
    }
}*/

int main(int argc,char* argv[])
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

    /* Define the device */
    dev = pcap_lookupdev(errbuf);//인터페이스 얻어오기
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    /* if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }*/
    /* Open the session in promiscuous mode */

    while(1)
    {
        /* The actual packet */

        handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);//피캣오픈픈
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return(2);
        }
        /* Compile and apply the filter */      //원하는 패킷만 잡기위해 필터링하는 함수로 pcap_compile,pcap_setfilter이용한다.
        /* if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
        /* Grab a packet */
        //    const u_char *packet;		/* The actual packet */
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


                printf("Packet infromation len : %d\n",header->len);

                if(packet!=NULL)
                {
                    eths=(Eths*)packet;
                    int datastart=14;
                    /*  cout<<"Eth destination :";
                    for(int i=0;i<6;i++)
                        printf("%02x ",eths->destination[i]);
                    cout<<endl<<"Eth source :";
                    for(int i=0;i<6;i++)
                        printf("%02x ",eths->source[i]);
                    cout<<endl;*/
                    if(eths->eth_type==8)
                    {
                        ips=(IPs*)(packet+14);
                        uint8_t a=(ips->header)&0x0F;

                        // inet_ntop(AF_INET, &a, buf, sizeof(1));
                        // int ipsize=atoi(buf);
                        int ipsize=4*a;

                        datastart+=ipsize;
                        /*     cout<<"IP destination :";
                        for(int i=0;i<4;i++)
                        {
                            inet_ntop(AF_INET,&ips->destination[i],buf,8);
                            printf("%s.",buf);
                        }
                        cout<<endl<<"IP Soure :";
                        for(int i=0;i<4;i++)
                        {
                            inet_ntop(AF_INET,&ips->source[i],buf,8);
                            printf("%s.",buf);
                        }
                        cout<<endl;*/

                        if(ips->protocol==0x06)
                        {
                            cout<<"Eth destination :";
                            for(int i=0;i<6;i++)
                                printf("%02x ",eths->destination[i]);
                            cout<<endl<<"Eth source :";
                            for(int i=0;i<6;i++)
                                printf("%02x ",eths->source[i]);
                            cout<<endl;


                            cout<<"IP destination :";
                            // for(int i=0;i<4;i++)
                            // {
                            //char buf2[100];
                            buf=(char*)malloc(32);
                            //  printf("ccc %02x\n",ips->destination[i]);
                            inet_ntop(AF_INET,&ips->destination,buf,32);
                            printf("%s.",buf);
                            free(buf);
                            // }
                            cout<<endl<<"IP Soure :";
                           // for(int i=0;i<4;i++)
                         //   {
                                buf=(char*)malloc(32);
                                inet_ntop(AF_INET,&ips->source,buf,32);
                                printf("%s.\n",buf);
                                free(buf);
                         //   }



                            tcps=(Tcps*)(packet+ipsize+14);
                         //   printf("ddd : %02x\n",tcps->offset);
                            uint8_t av=(tcps->offset)>>4;
                           //         printf("after : %02",av);
                            av=av&0x0F;

                            int tcpsize=av*4;
                           // printf("\n%d\n",tcpsize);
                          //  tcpsize=tcpsize*4;
                            datastart+=tcpsize;
                            buf=(char*)malloc(16);
                            inet_ntop(AF_INET,&tcps->source,buf,16);
                            printf("TCP source port : %d \n",ntohs(tcps->source));
                            free(buf);
                            buf=(char*)malloc(16);
                            inet_ntop(AF_INET,&tcps->destination,buf,16);

                            printf("TCP destination port : %d\n",ntohs(tcps->destination));
                            free(buf);
                           if(ntohs(tcps->source)==80 || ntohs(tcps->destination)==80)
                            {
                               // buf=(char*)malloc(16);
                              // inet_ntop(AF_INET,&ips->total,buf,16);
                              //  printf("test :%s\n",buf);
                                int datasizes=ntohs(ips->total);
                               // printf("dfdfd %d \n",ips->total);
                              //  printf("ip size : %d",ipsize);
                              //  printf("des size : %d \n",tcpsize);

                                datasizes-=ipsize;
                                datasizes-=tcpsize;
                                if(datasizes<0)
                                    datasizes=0;
                           //     printf("a :%d \n",datastart);
                             //           printf("b : %d \n",datasizes);
                                for(int i=datastart;datasizes+datastart;i++)
                                    printf("%c",*(packet+i));
                                free(buf);
                            }
                        }
                    }
                }

                break;

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
