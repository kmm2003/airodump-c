#include <iostream>
#include <string> 
#include <vector>
#include <map>
#include <utility>
#include <unistd.h>
#include <stdio.h>
#include <pcap.h>
#include <ncurses.h>

enum status
{
  SUCCESS,
  FAIL,
  NEXT
};

struct RADIOTAP_HEADER 
{
  u_int8_t    version;     
  u_int8_t    pad;
  u_int16_t   len;         
  u_int8_t		present[8];  
	u_int8_t		flags;
	u_int8_t		dataRate;
	u_int16_t		channelFrequency;
	u_int16_t		channelFlags;  
	u_int8_t		antennaSignal; //PWR
	u_int8_t		antenna;
	u_int16_t		rxFlags; 
	u_int8_t		antennaSignalT;
	u_int8_t		antennaT;
};

struct BEACON_FRAME
{
	u_int16_t frameControl; //0x0008
	u_int16_t duration;
	u_int8_t destinationAddr[6];
	u_int8_t sourceAddr[6];
	u_int8_t bssid[6];
	u_int16_t seqNum;
};

struct WIRELESS_MANAGER
{
	u_int8_t timestamp[8];
	u_int16_t beaconInterval;
	u_int16_t capabilityInfo;
};

struct SSID_PARAMETER
{
	u_int8_t tagName;
	u_int8_t tagLength;
};

struct WIRELESS_PACKET
{
	RADIOTAP_HEADER ieee80211RadiotapHeader;
	BEACON_FRAME beaconFrame;
	WIRELESS_MANAGER wirelessManager;
	SSID_PARAMETER ssidParameter;
};

class Airodump 
{
private:
	pcap_t* pcap;	
  const u_char* packet;
  std::map<std::string,std::vector<std::string>> apInfo; 

public:
  Airodump(char * dev);
  ~Airodump();
  int airodump();

private:
  int getWirelessPacket(pcap_t* pcap);
  void convertPacket();
	void printLog();
	std::string getESSID();
	std::string getBSSID();
};
