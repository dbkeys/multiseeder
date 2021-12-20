#ifndef _BITCOIN_H_
#define _BITCOIN_H_ 1

#include "protocol.h"

#ifndef SEEDER_COUNT
#define SEEDER_COUNT 10
#endif

extern int TempMainThreadNumber;
extern int nCurrentBlock[SEEDER_COUNT];
extern std::string sAppName;
extern unsigned char cfg_message_start[SEEDER_COUNT][4];
bool TestNode(const CService &cip, int &ban, int &client, std::string &clientSV, int &blocks, bool &insync, std::vector<CAddress>* vAddr, uint64_t& services);

#endif