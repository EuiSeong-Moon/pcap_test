#include <iostream>
#include <pcap.h>
#include <cstring>
#include <cmath>
#include <cstdlib>
#include <stdlib.h>

using namespace std;
class Eths
{
public:
    const unsigned char* destination;
    const unsigned char* source;
    const unsigned char* pickip;

    void print(void)
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
};

class IPs
{
public:
    const unsigned char* destination;
    const unsigned char* source;
    const unsigned char* pickip;

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
};
class Tcps
{
public:
    const unsigned char* destination;       const u_char *packet;		/* The actual packet */

    const unsigned char* source;

    void print(void)
    {
        printf("tcp destination ");
       // for(int i=0;i<2;i++)
        int num1=pow(2,4);
        num1*=*(destination);
        int num2=*(destination+1);
            printf(": %d",num1+num2);

        cout<<endl;
        printf("tcp source ");
      //  for(int i=0;i<2;i++)
        num1=pow(2,4);
        num1*=*(source);
        num2=*(source+1);
            printf(": %d",num1+num2);
        cout<<endl;
    }
};

void test (const u_char *packets,bpf_u_int32 lens)
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
            for(i=0;i<lens-54;i++)
            {
                if(i==0)
                    printf("DATA \n");
             //   char aaa[100];
                //itoa(*(packets+i),aaa,10);
                printf("%c ",*(packets+i));
                if(i!=0 && (i&7==0))
                    cout<<endl;
            }
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
   delete eths;
   delete ips;
   delete tcps;
    }
}

int main()
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
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */

while(1)
{
    const u_char *packet;		/* The actual packet */

    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);//피캣오픈픈
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */      //원하는 패킷만 잡기위해 필터링하는 함수로 pcap_compile,pcap_setfilter이용한다.
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    /* Grab a packet */
//    const u_char *packet;		/* The actual packet */
   while((res = pcap_next_ex(handle, &header,&packet)) >= 0){

       if(res == 0)
           /* Timeout elapsed */
           continue;

       /* convert the timestamp to readable format */
       local_tv_sec = header->ts.tv_sec;
       ltime=localtime(&local_tv_sec);
       strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

       printf("Packet infromation len : %d\n",header->len);
      // printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
       if(packet!=NULL)
           {
           /*    for(int i=0;i<header->len;i++)
               {
                  printf("%02x  ",*(packet+i));
               }
                  cout<<endl;*/
                 test(packet,header->len);

           }



   }

   if(res == -1){
       printf("Error reading the packets: %s\n", pcap_geterr(handle));
       return -1;

   }
           //패킷의 길이와 헤더정보가 넘어오고 pcap_next의 리턴 값이 바로 패킷이다 이더넷부터 쭉쭉 다있는 것 이 것이용 6바이트 6바이트출력해서 값얻어냄 분석시작
    //0x08로 뒤에 얹혀지는게 ip인거알아내면 또 읽어들여서 뒤에 바이트가지고, 분석 그다음 또 프로토콜로 다음올라가는거 확인 데이터부분은 앞의 10byte만출력
    //pcap_next는 타임아웃인지 못받은건지 알 수 없다 다 null만나옴 때문에 pcap_next_exe이걸 사용하면 타임아웃인지 아님 fail로못받은건지 오류의원인을 알수있다.
    /* Print its length */


   /*printf("Jacked a packet with length of [%d]\n", header.len);   //  new next case
     And close the session*/


 //   test (packet);
}
  //  pcap_loop(handle,0,test,NULL);
    pcap_close(handle);

    return(0);
}
