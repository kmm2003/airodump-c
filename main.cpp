#include "airodump.h"
#include <stdbool.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
	if (argc != 2){
    printf("syntax: airodump <interface>\n");
	  printf("sample: airodump wlan0\n");
    exit(0);
  }
		
	Airodump airodump(argv[1]);
	airodump.airodump();
	return 0;
}