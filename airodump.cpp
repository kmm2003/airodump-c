#include "airodump.h"

Airodump::Airodump(char* dev)
{
  param.dev_ = dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
    exit(1);
	}
}

Airodump::~Airodump(){
  pcap_close(pcap);  
}


int Airodump::airodump()
{
  initscr();
  move(0,0);

  while(1)
  {
      int status = getWirelessPacket(pcap);
      if (status == FAIL)
          break; 
      if (status == NEXT)
          continue;
      
      convertPacket();
      printLog();
  }

  getch();

  return 0;
}

int Airodump::getWirelessPacket(pcap_t* pcap)
{
  
	struct pcap_pkthdr* header;
	int res = pcap_next_ex(pcap, &header, &packet);
	if (res == 0) return NEXT;
	if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
		printf("pcap error response %d(%s)\n", res, pcap_geterr(pcap));
		return FAIL;
	}
  
  return SUCCESS;
	  
}

void Airodump::convertPacket()
{
  WIRELESS_PACKET* wirelessPacket = (WIRELESS_PACKET*)packet;
  
  if(wirelessPacket->beaconFrame.frameControl != 0x80)
      return;    

  std::string Bssid = getBSSID();
  std::string Essid = getESSID();
  
  
  std::vector<std::string> info;
  info.push_back(Essid);

  apInfo[Bssid] = info;
}

void Airodump::printLog()
{
  clear();
  printw("BSSID\t\t\tESSID\n");
  for(auto iter = apInfo.begin(); iter != apInfo.end(); iter++)
  {
    std::string Bssid = iter->first;
    std::string Essid = iter->second[0];

    printw("%s\t%s\n",Bssid.c_str(),Essid.c_str());
    refresh();
  }    
}

std::string Airodump::getBSSID()
{
  WIRELESS_PACKET* wirelessPacket = (WIRELESS_PACKET*)packet;  
  char mac[31];
  snprintf(mac,31,"%02X:%02X:%02X:%02X:%02X:%02X",
          wirelessPacket->beaconFrame.bssid[0],
          wirelessPacket->beaconFrame.bssid[1],
          wirelessPacket->beaconFrame.bssid[2],
          wirelessPacket->beaconFrame.bssid[3],
          wirelessPacket->beaconFrame.bssid[4],
          wirelessPacket->beaconFrame.bssid[5]);
  return std::string(mac);
}

std::string Airodump::getESSID()
{
  int essidPosition = sizeof(WIRELESS_PACKET);
  WIRELESS_PACKET* wirelessPacket = (WIRELESS_PACKET*)packet;  
  u_char* data = (u_char*)packet + essidPosition;
  std::string Essid;
  if(data[0] == '\0')
  {
      Essid = "This is hidden AP";
      return Essid;
  }

  for(int i = 0; i < wirelessPacket->ssidParameter.tagLength; i++)
    Essid += data[i];

  return Essid;
}