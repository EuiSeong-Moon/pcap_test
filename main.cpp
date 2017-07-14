#include <iostream>
#include <pcap.h>
#include <cstring>

using namespace std;
class Eths
{
public:
    const unsigned char* destination;
    const unsigned char* source;
    const unsigned char* pickip;
};



void test (const u_char *packets,bpf_u_int32 lens)
{
    if(packets!=NULL)
    {
    Eths* eths=new Eths;
    //strncpy(eths->destination,packets,6);
    eths->destination=packets+0;
   eths->source=packets+6;
   eths->pickip=packets+8;

    //cout<<packets<<endl;
    cout<<"i;m testing"<<endl;
    //printf("%s",eths->source);

   printf("%x \n",*(eths->destination));
   printf("%x \n",*(eths->source));
   printf("%x \n",*(eths->pickip));
   delete eths;
    }
}

int main()
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression */ //23번포트면 텔렛 80프토면 웹통신만 잡겟다는의미이다.
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header;	/* The header that pcap gives us */

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
    packet = pcap_next(handle, &header);        //패킷의 길이와 헤더정보가 넘어오고 pcap_next의 리턴 값이 바로 패킷이다 이더넷부터 쭉쭉 다있는 것 이 것이용 6바이트 6바이트출력해서 값얻어냄 분석시작
    //0x08로 뒤에 얹혀지는게 ip인거알아내면 또 읽어들여서 뒤에 바이트가지고, 분석 그다음 또 프로토콜로 다음올라가는거 확인 데이터부분은 앞의 10byte만출력
    //pcap_next는 타임아웃인지 못받은건지 알 수 없다 다 null만나옴 때문에 pcap_next_exe이걸 사용하면 타임아웃인지 아님 fail로못받은건지 오류의원인을 알수있다.
    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);
    /* And close the session */
    if(packet!=NULL)
    {
        for(int i=0;i<header.len;i++)
        {
           printf("%x  ",*(packet+i));
        }
           cout<<endl;
          test(packet,header.len);
    }

    pcap_close(handle);
 //   test (packet);
}
  //  pcap_loop(handle,0,test,NULL);
    pcap_close(handle);

    return(0);
}
