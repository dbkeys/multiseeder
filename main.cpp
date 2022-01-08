#include <algorithm>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <atomic>
#include <iostream>
#include <string>
#include <curl/curl.h>
#include <libconfig.h++>
#include <ncurses.h>
#include "bitcoin.h"
#include "db.h"

#include <fstream>
#include <dirent.h> 
// https://stackoverflow.com/questions/39231363/fatal-error-filesystem-no-such-file-or-directory
// #include <filesystem>
#include <experimental/filesystem>
//using namespace std::filesystem;

using namespace std;
using namespace libconfig;

#include <sstream>



// [Major].[Minor].[Patch].[Build].[letter]
// [0].[1].[1].[0].[c]
const char* dnsseeder_version = "0.1.1.0.jk.multi\0x0";


#define SEEDER_COUNT 10

int actualMainThreadCount = 0;

int TempMainThreadNumber=0;
bool fDNS[SEEDER_COUNT] = {true,};

int nThreads[SEEDER_COUNT]={96,};
int nPort[SEEDER_COUNT]={53,};
int nDnsThreads[SEEDER_COUNT]={4,};
const char *mbox[SEEDER_COUNT]={0,};
const char *ns[SEEDER_COUNT]={0,};
const char *host[SEEDER_COUNT]={0,};
const char *ip_addr[SEEDER_COUNT]={0,};

string* configPaths[SEEDER_COUNT]={0,};
string* coinNames[SEEDER_COUNT]={0,};
  
bool fDumpAll = false;
bool bCurrentBlockFromExplorer[SEEDER_COUNT] = {false,};
string sAppName = "generic-seeder";
string sAppVersion = "1.1.0";
string sForceIP;
string sCurrentBlock[SEEDER_COUNT]= {"","","",""};
long long int nCurrentBlock[SEEDER_COUNT] = {-1,};
long long int nMaxBlockHeight[SEEDER_COUNT]={0,};
int nDefaultBlockHeight[SEEDER_COUNT] = {-1};

string	cfg_blockchain_name[SEEDER_COUNT]= {"","","",""};
int cfg_protocol_version[SEEDER_COUNT]={0,};
int cfg_init_proto_version[SEEDER_COUNT]={0,};
int cfg_min_peer_proto_version[SEEDER_COUNT]={0,};
int cfg_caddr_time_version[SEEDER_COUNT]={0,};
unsigned char cfg_message_start[SEEDER_COUNT][4]= {"","","",""};
int cfg_wallet_port[SEEDER_COUNT]={0,};
string cfg_explorer_url[SEEDER_COUNT]= {"","","",""};
string cfg_explorer_url2[SEEDER_COUNT]= {"","","",""};
int cfg_explorer_requery_seconds[SEEDER_COUNT]={0,};

string sSeeds[SEEDER_COUNT][11];
string *seeds[SEEDER_COUNT];// = sSeeds;

class CDnsSeedOpts {
public:
//  string blockchain_name ??
  int fWipeBan;
  int fWipeIgnore;
  int fDumpAll;
  //int nThreads;
  //int nPort;
  //int nDnsThreads;
  //const char *mbox;
  //const char *ns;
  //const char *host;
  const char *tor;
  //const char *ip_addr;
  const char *ipv4_proxy;
  const char *ipv6_proxy;
  const char *force_ip;
  std::set<uint64_t> filter_whitelist;

  /* Need to distinguish between several blockchains and the DNS seeder-server giving out information */
  CDnsSeedOpts() : /*nThreads(96), nDnsThreads(4), ip_addr("::"), nPort(53), mbox(NULL), ns(NULL), host(NULL),*/ tor(NULL), fWipeBan(false), fWipeIgnore(false), fDumpAll(false), ipv4_proxy(NULL), ipv6_proxy(NULL), force_ip("a") {}

  void ParseCommandLine(int argc, char **argv) {
    static const char *help = "generic-seeder\n"
                              "Usage: %s -h <host> -n <ns> [-m <mbox>] [-t <threads>] [-p <port>]\n"
                              "\n"
                              "Options:\n"
                              "-h <host>       Name of the sub-domain to name-serve\n"
                              "-n <ns>         IP address of this nameserver\n"
                              "-m <mbox>       E-Mail address reported in SOA records\n"
                              "-t <threads>    Number of crawlers to run in parallel (default 96)\n"
                              "-d <threads>    Number of DNS server threads (default 4)\n"
                              "-a <address>    Address to listen on (default ::)\n"
                              "-p <port>       UDP port to listen on (default 53)\n"
                              "-o <ip:port>    Tor proxy IP/Port\n"
                              "-i <ip:port>    IPV4 SOCKS5 proxy IP/Port\n"
                              "-k <ip:port>    IPV6 SOCKS5 proxy IP/Port\n"
                              "-w f1,f2,...    Allow these flag combinations as filters\n"
                              "-f <ip version> Force connections to nodes of a specific ip type\n"
                              "                valid options: a = all, 4 = IPv4, 6 = IPv6 (default a)\n"
                              "--wipeban       Wipe list of banned nodes\n"
                              "--wipeignore    Wipe list of ignored nodes\n"
                              "--dumpall       Dump all unique nodes\n"
                              "-?, --help      Show this text\n"
                              "\n";
    bool showHelp = false;

    while(1) {
      static struct option long_options[] = {
        {"host", required_argument, 0, 'h'},
        {"ns",   required_argument, 0, 'n'},
        {"mbox", required_argument, 0, 'm'},
        {"threads", required_argument, 0, 't'},
        {"dnsthreads", required_argument, 0, 'd'},
        {"address", required_argument, 0, 'a'},
        {"port", required_argument, 0, 'p'},
        {"onion", required_argument, 0, 'o'},
        {"proxyipv4", required_argument, 0, 'i'},
        {"proxyipv6", required_argument, 0, 'k'},
        {"filter", required_argument, 0, 'w'},
        {"forceip", required_argument, 0, 'f'},
        {"wipeban", no_argument, &fWipeBan, 1},
        {"wipeignore", no_argument, &fWipeIgnore, 1},
        {"dumpall", no_argument, &fDumpAll, 1},
        {"help", no_argument, 0, '?'},
        {0, 0, 0, 0}
      };
      int option_index = 0;
      // Date & Time Display
      int c = getopt_long(argc, argv, "h:n:m:t:a:p:d:o:i:k:w:f:?", long_options, &option_index);
      if (c == -1) break;
      switch (c) {
        case 'h': {
          //host = optarg;
          break;
        }
        
        case 'm': {
          //mbox = optarg;
          break;
        }
        
        case 'n': {
          //ns = optarg;
          break;
        }
        
        case 't': {
          //int n = strtol(optarg, NULL, 10);
          //if (n > 0 && n < 1000) nThreads = n;
          break;
        }

        case 'd': {
          //int n = strtol(optarg, NULL, 10);
          //if (n > 0 && n < 1000) nDnsThreads = n;
          break;
        }

        case 'a': {
          /*if (strchr(optarg, ':')==NULL) {
            char* ip4_addr = (char*) malloc(strlen(optarg)+8);
            strcpy(ip4_addr, "::FFFF:");
            strcat(ip4_addr, optarg);
            ip_addr = ip4_addr;
          } else {
            ip_addr = optarg;
          }*/
          break;
        }

        case 'p': {
          //int p = strtol(optarg, NULL, 10);
          //if (p > 0 && p < 65536) nPort = p;
          break;
        }

        case 'o': {
          tor = optarg;
          break;
        }

        case 'i': {
          ipv4_proxy = optarg;
          break;
        }

        case 'k': {
          ipv6_proxy = optarg;
          break;
        }

        case 'w': {
          char* ptr = optarg;
          while (*ptr != 0) {
            unsigned long l = strtoul(ptr, &ptr, 0);
            if (*ptr == ',') {
                ptr++;
            } else if (*ptr != 0) {
                break;
            }
            filter_whitelist.insert(l);
          }
          break;
        }

        case 'f': {
          force_ip = optarg;
          break;
        }

        case '?': {
          showHelp = true;
          break;
        }
      }
    }
    if (filter_whitelist.empty()) {
        filter_whitelist.insert(NODE_NETWORK); // x1
        filter_whitelist.insert(NODE_NETWORK | NODE_BLOOM); // x5
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS); // x9
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS | NODE_COMPACT_FILTERS); // x49
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS | NODE_BLOOM); // xd
        filter_whitelist.insert(NODE_NETWORK_LIMITED); // x400
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_BLOOM); // x404
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS); // x408
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_COMPACT_FILTERS); // x448
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_BLOOM); // x40c
    }
    if (host != NULL && ns == NULL) showHelp = true;
    if (showHelp) {
        fprintf(stderr, help, argv[0]);
        exit(0);
    }
  }
};

#include "dns.h"

CAddrDb db[SEEDER_COUNT];

CDnsSeedOpts opts;


class ThreadCrawlerArgs{
public:
	int nThreads;
	int MainThreadNumber;
};

pthread_mutex_t mutex_mainthreadnumber;
/*pthread_mutex_t mutex_mainthreadnumberCrawlerTestNode;
pthread_mutex_t mutex_mainthreadnumber2;
pthread_mutex_t mutex_mainthreadnumber3;
pthread_mutex_t mutex_mainthreadnumber4;*/

extern "C" void* ThreadCrawler(void* data) {
  ThreadCrawlerArgs tArgs = *(ThreadCrawlerArgs*)data;
  Sleep(3000);
  //printf("tArgs.nThreads:%d\n", tArgs.nThreads);
  do {
	  /*if(tArgs.MainThreadNumber != 1){
			Sleep(1000);
		  continue;
	  }*/

	pthread_mutex_lock(&mutex_mainthreadnumber);
    TempMainThreadNumber = tArgs.MainThreadNumber;
    std::vector<CServiceResult> ips;
    int wait = 5;
    db[tArgs.MainThreadNumber].GetMany(ips, 16, wait);
    pthread_mutex_unlock(&mutex_mainthreadnumber);
	
	  //pthread_mutex_unlock(&mutex_mainthreadnumberCrawlerTestNode);
	  
    int64 now = time(NULL);
    if (ips.empty()) {
              //cout << "crawler" << now << endl;
      wait *= 1000;
      wait += rand() % (500 * tArgs.nThreads);
      Sleep(wait);
	  //pthread_mutex_unlock(&mutex_mainthreadnumberCrawlerTestNode);
      continue;
    }

    		//cout << "crawler 2****** " << now << endl;

    pthread_mutex_lock(&mutex_mainthreadnumber);
    TempMainThreadNumber = tArgs.MainThreadNumber;
    vector<CAddress> addr;
    pthread_mutex_unlock(&mutex_mainthreadnumber);
    
	//printf("|\n");
    for (int i=0; i<ips.size(); i++) {

      pthread_mutex_lock(&mutex_mainthreadnumber);
      TempMainThreadNumber = tArgs.MainThreadNumber;
      CServiceResult &res = ips[i];
      pthread_mutex_unlock(&mutex_mainthreadnumber);

      res.nBanTime = 0;
      res.nClientV = 0;
      res.nHeight = 0;
      res.strClientV = "";
      res.bInSync = false;
      res.services = 0;
      bool getaddr = res.ourLastSuccess + 86400 < now;
	//printf("_\n");
	  //pthread_mutex_lock(&mutex_mainthreadnumber);
	  TempMainThreadNumber=tArgs.MainThreadNumber;
      res.fGood = TestNode(tArgs.MainThreadNumber, res.service,res.nBanTime,res.nClientV,res.strClientV,res.nHeight,res.bInSync,getaddr ? &addr : NULL, res.services);
      //printf("fGood:%d %d.%d.%d.%d\n", res.fGood, res.service.ip[0],res.service.ip[1],res.service.ip[2],res.service.ip[3]);
	  //pthread_mutex_unlock(&mutex_mainthreadnumber);
    }
	
	  pthread_mutex_lock(&mutex_mainthreadnumber);
      TempMainThreadNumber = tArgs.MainThreadNumber;
	  db[tArgs.MainThreadNumber].ResultMany(ips);
      db[tArgs.MainThreadNumber].Add(addr);
      pthread_mutex_unlock(&mutex_mainthreadnumber);
	
	
	  //pthread_mutex_unlock(&mutex_mainthreadnumberCrawlerTestNode);
  } while(1);
  return nullptr;
}

extern "C" int GetIPList(void *thread, char *requestedHostname, addr_t *addr, int max, int ipv4, int ipv6);

class CDnsThread {
public:
  struct FlagSpecificData {
      int nIPv4, nIPv6;
      std::vector<addr_t> cache;
      time_t cacheTime;
      unsigned int cacheHits;
      FlagSpecificData() : nIPv4(0), nIPv6(0), cacheTime(0), cacheHits(0) {}
  };

  dns_opt_t dns_opt; // must be first
  const int id;
  std::map<uint64_t, FlagSpecificData> perflag;
  std::atomic<uint64_t> dbQueries;
  std::set<uint64_t> filterWhitelist;
  
  int MainThreadNumber;

  void cacheHit(uint64_t requestedFlags, bool force = false) {
    static bool nets[NET_MAX] = {};
    if (!nets[NET_IPV4]) {
        nets[NET_IPV4] = true;
        nets[NET_IPV6] = true;
    }
    time_t now = time(NULL);
    FlagSpecificData& thisflag = perflag[requestedFlags];
    thisflag.cacheHits++;
    if (force || thisflag.cacheHits * 400 > (thisflag.cache.size()*thisflag.cache.size()) || (thisflag.cacheHits*thisflag.cacheHits * 20 > thisflag.cache.size() && (now - thisflag.cacheTime > 5))) {
      set<CNetAddr> ips;
      db[MainThreadNumber].GetIPs(ips, requestedFlags, 1000, nets);
      dbQueries++;
      thisflag.cache.clear();
      thisflag.nIPv4 = 0;
      thisflag.nIPv6 = 0;
      thisflag.cache.reserve(ips.size());
      for (set<CNetAddr>::iterator it = ips.begin(); it != ips.end(); it++) {
        struct in_addr addr;
        struct in6_addr addr6;
        if ((*it).GetInAddr(&addr)) {
          addr_t a;
          a.v = 4;
          memcpy(&a.data.v4, &addr, 4);
          thisflag.cache.push_back(a);
          thisflag.nIPv4++;
        } else if ((*it).GetIn6Addr(&addr6)) {
          addr_t a;
          a.v = 6;
          memcpy(&a.data.v6, &addr6, 16);
          thisflag.cache.push_back(a);
          thisflag.nIPv6++;
        }
      }
      thisflag.cacheHits = 0;
      thisflag.cacheTime = now;
    }
  }

  CDnsThread(CDnsSeedOpts* opts, int idIn, int mainThreadNumber) 
    : id(idIn),
	MainThreadNumber(mainThreadNumber)
  {
    dns_opt.host = host[mainThreadNumber];
    dns_opt.ns = ns[mainThreadNumber];
    dns_opt.mbox = mbox[mainThreadNumber];
    dns_opt.datattl = 3600;
    dns_opt.nsttl = 40000;
    dns_opt.cb = GetIPList;
    dns_opt.addr = ip_addr[mainThreadNumber];
    dns_opt.port = nPort[mainThreadNumber];
    dns_opt.nRequests = 0;
    dbQueries = 0;
    perflag.clear();
    filterWhitelist = opts->filter_whitelist;
  }

  void run() {
	//while(1) // there's an infinite for loop alread within dnsserver func
	dnsserver(&dns_opt);
  }
};

vector<CDnsThread*> dnsThread[SEEDER_COUNT];

extern "C" int GetIPList(void *data, char *requestedHostname, addr_t* addr, int max, int ipv4, int ipv6) {
  CDnsThread *thread = (CDnsThread*)data;

  //printf("requestedHostname: %s %s\n\r", requestedHostname, thread->dns_opt.host);
  ofstream logger;
  logger.open("/var/log/multiseeder.log", std::ios_base::app);
  logger << (thread->dbQueries+1) << ": " << requestedHostname << "  ";
  //logger << "queryline; " << (thread->dbQueries+1) << "; " << requestedHostname << endl;

  uint64_t requestedFlags = 0;
  int hostlen = strlen(requestedHostname);
  if (hostlen > 1 && requestedHostname[0] == 'x' && requestedHostname[1] != '0') {
    char *pEnd;
    uint64_t flags = (uint64_t)strtoull(requestedHostname+1, &pEnd, 16);
    if (*pEnd == '.' && pEnd <= requestedHostname+17 && std::find(thread->filterWhitelist.begin(), thread->filterWhitelist.end(), flags) != thread->filterWhitelist.end())
      requestedFlags = flags;
    else
      return 0;
  }
  else if (strcasecmp(requestedHostname, thread->dns_opt.host))
    return 0;
  thread->cacheHit(requestedFlags);
  auto& thisflag = thread->perflag[requestedFlags];
  unsigned int size = thisflag.cache.size();
  unsigned int maxmax = (ipv4 ? thisflag.nIPv4 : 0) + (ipv6 ? thisflag.nIPv6 : 0);
  if (max > size)
    max = size;
  if (max > maxmax)
    max = maxmax;
  int i=0;
  while (i<max) {
    int j = i + (rand() % (size - i));
    do {
        bool ok = (ipv4 && thisflag.cache[j].v == 4) ||
                  (ipv6 && thisflag.cache[j].v == 6);
        if (ok) break;
        j++;
        if (j==size)
            j=i;
    } while(1);
    addr[i] = thisflag.cache[j];
    thisflag.cache[j] = thisflag.cache[i];
    thisflag.cache[i] = addr[i];
        if(addr[i].v == 4){
                //logger << "v4 ";
                logger << (int)addr[i].data.v4[0];
                for (int byte = 1; byte < 4; byte++)
                        logger << "." << (int)addr[i].data.v4[byte];
                logger << "; ";
                //logger << "; " << endl;
        }
        else if (addr[i].v == 6) {
                ///logger << "v6 ";
                logger << (int)addr[i].data.v6[0];
                for (int byte = 1; byte < 16; byte++)
                        logger << "." << (int)addr[i].data.v6[byte];
                logger << "; ";
                //logger << "; " << endl;
        }
    i++;
  }
  logger << endl;
  logger.close();
  return max;
}


extern "C" void* ThreadDNS(void* arg) {
	
  CDnsThread *thread = (CDnsThread*)arg;
  thread->run();
	
  return nullptr;
}

int StatCompare(const CAddrReport& a, const CAddrReport& b) {
  if (a.uptime[4] == b.uptime[4]) {
    if (a.uptime[3] == b.uptime[3]) {
      return a.clientVersion > b.clientVersion;
    } else {
      return a.uptime[3] > b.uptime[3];
    }
  } else {
    return a.uptime[4] > b.uptime[4];
  }
}

bool is_numeric(char *string) {
    int sizeOfString = strlen(string);
    int iteration = 0;
    bool isNumeric = true;

    if (sizeOfString > 0) {
        while(iteration < sizeOfString)
        {
            if (!isdigit(string[iteration]))
            {
                isNumeric = false;
                break;
            }

            iteration++;
        }
    } else {
        isNumeric = false;
    }

    return isNumeric;
}

const char* charReplace(const char *str, char ch1, char ch2)
{
    char *newStr = new char[strlen(str)+1];
    int n = 0;

    while(*str!='\0')
    {
        if (*str == ch1) {
            newStr[n] = ch2;
        } else {
            newStr[n] = *str;
        }
        str++;
        n++;
    }
    newStr[n] = '\0';
    return (const char *)newStr;
}

size_t writeCallback(char* buf, size_t size, size_t nmemb, void* up) {
	int __TempMainThreadNumber = *(int*)up;
    for (int c = 0; c<size*nmemb; c++) {
        sCurrentBlock[__TempMainThreadNumber].push_back(buf[c]);
		//printf("%s\n", sCurrentBlock[__TempMainThreadNumber].c_str());
    }
    return size*nmemb; //tell curl how many bytes we handled
}

long long int readBlockHeightFromExplorer(string sExplorerURL, int __TempMainThreadNumber) {
    long long  nReturn = -1;

    sCurrentBlock[__TempMainThreadNumber] = "";
    CURL* curl;
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, sExplorerURL.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &__TempMainThreadNumber);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    if (!sCurrentBlock[__TempMainThreadNumber].empty() && sCurrentBlock[__TempMainThreadNumber][0] != 0 && is_numeric(&(sCurrentBlock[__TempMainThreadNumber][0u]))) {
        // Block height from explorer was read successfully
		try{
			nReturn = std::stoll(sCurrentBlock[__TempMainThreadNumber]);
			//printf("nReturn:%d\n", nReturn);
		}catch(...){
			printf("stoi exc. sCurrentBlock: %s\n", sCurrentBlock[__TempMainThreadNumber].c_str());
		}
    }

    return nReturn;
}

int hex_string_to_int(std::string sHexString) {
    int x;   
    std::stringstream ss;
    ss << std::hex << sHexString;
    ss >> x;
    return x;
}


extern "C" void* ThreadBlockReader(void* _MainThreadNumber) {
	int MainThreadNumber = *(int*)_MainThreadNumber;
	
	Sleep(2500);
			
	// Check if block explorer 1 is set
	if (cfg_explorer_url[MainThreadNumber].compare("") != 0) {
		do {
			/*if(MainThreadNumber != 1)
			{
				Sleep(1000);
				continue;
			}*/
			pthread_mutex_lock(&mutex_mainthreadnumber);
			
			//TempMainThreadNumber = MainThreadNumber;
			// Read from block explorer 1
			
            long long int returnedBlockForFindingMax = 0;
            long long int nReturnBlock = readBlockHeightFromExplorer(cfg_explorer_url[MainThreadNumber], MainThreadNumber);
			returnedBlockForFindingMax = nReturnBlock;

			if (nReturnBlock == -1 || nReturnBlock == nCurrentBlock[MainThreadNumber]) {
				// Block explorer 1 failed to return a proper block height or the value is the same as the previous value
				// Check if block explorer 2 is set
				if (cfg_explorer_url2[MainThreadNumber].compare("")) {
					// Save the value from explorer 1
                    long long int nReturnBlockSave = nReturnBlock;
					// Read from block explorer 2
					nReturnBlock = readBlockHeightFromExplorer(cfg_explorer_url2[MainThreadNumber], MainThreadNumber);
					
					returnedBlockForFindingMax = nReturnBlock;

					if (nReturnBlockSave == -1 && nReturnBlock == -1) {
						// Block explorer 2 failed to return a proper block height
						nCurrentBlock[MainThreadNumber] = nDefaultBlockHeight[MainThreadNumber];
						bCurrentBlockFromExplorer[MainThreadNumber] = false;
					} else {
						// Block explorer 2 returned a block height
						// Compare and take the higher value from both block explorers
						nCurrentBlock[MainThreadNumber] = (nReturnBlock > nReturnBlockSave ? nReturnBlock : nReturnBlockSave);
						nDefaultBlockHeight[MainThreadNumber] = nCurrentBlock[MainThreadNumber];
						bCurrentBlockFromExplorer[MainThreadNumber] = true;
					}
				} else {
					// No block explorer 2 is set
					nCurrentBlock[MainThreadNumber] = (nReturnBlock == -1 ? nDefaultBlockHeight[MainThreadNumber] : nReturnBlock);
					bCurrentBlockFromExplorer[MainThreadNumber] = nReturnBlock != -1;
				}
			} else {
				// Block explorer 1 returned a block height
				nCurrentBlock[MainThreadNumber] = nReturnBlock;
				nDefaultBlockHeight[MainThreadNumber] = nCurrentBlock[MainThreadNumber];
				bCurrentBlockFromExplorer[MainThreadNumber] = true;
			}
			
			if(returnedBlockForFindingMax > nMaxBlockHeight[MainThreadNumber])
				nMaxBlockHeight[MainThreadNumber] = returnedBlockForFindingMax;
			
			
			pthread_mutex_unlock(&mutex_mainthreadnumber);
			
				
			Sleep(cfg_explorer_requery_seconds[MainThreadNumber] * 1000);
		} while(1);
	} else {
		// No block explorers are set so default to getting the hardcoded block height
		nCurrentBlock[MainThreadNumber] = nDefaultBlockHeight[MainThreadNumber];
		bCurrentBlockFromExplorer[MainThreadNumber] = false;
	}
			
	return nullptr;
}


extern "C" void* ThreadDumper(void* _MainThreadNumber) {
	int MainThreadNumber = *(int*)_MainThreadNumber;
  int count = 0;
  do {
    Sleep(100000 << count); // First 100s, than 200s, 400s, 800s, 1600s, and then 3200s forever
	
	pthread_mutex_lock(&mutex_mainthreadnumber);
	TempMainThreadNumber = MainThreadNumber;
	
    if (count < 5)
        count++;
    {
      vector<CAddrReport> v = db[MainThreadNumber].GetAll();
      sort(v.begin(), v.end(), StatCompare);
	  ostringstream os;
	  os << "/usr/local/sDNS." << *coinNames[MainThreadNumber] << "/dnsseed.dat.new";
      FILE *f = fopen(os.str().c_str(),"w+");
      if (f) {
        {
          CAutoFile cf(f);
          cf << db[MainThreadNumber];
        }
		ostringstream os2;
	    os2 << "/usr/local/sDNS." << *coinNames[MainThreadNumber] << "/dnsseed.dat";
        rename(os.str().c_str(), os2.str().c_str());
      }
	  ostringstream osDump;
	  osDump << "/usr/local/sDNS." << *coinNames[MainThreadNumber] << "/dnsseed.dump";
	  
      FILE *d = fopen(osDump.str().c_str(), "w");
      if(!d)
      {
	      move(5,5);
	      clrtoeol();
	      printw("file not exist %s\n", osDump.str().c_str());
	      //exit(0);
      }
      else{
	  fprintf(d, "# address                                        good  lastSuccess    %%(2h)   %%(8h)   %%(1d)   %%(7d)  %%(30d)  blocks      svcs  version\n");
      double stat[5]={0,0,0,0,0};
      for (vector<CAddrReport>::const_iterator it = v.begin(); it < v.end(); it++) {
        CAddrReport rep = *it;

		if (fDumpAll) {
			// Show complete list of nodes with all applicable info gathered for each
			char cversionbuffer[7];
			snprintf(cversionbuffer, 7, "%d", rep.clientVersion);
			char blockbuffer[9];
			snprintf(blockbuffer, 9, "%d", rep.blocks);
			fprintf(d, "%-47s  %4d  %11" PRId64 "  %6.2f%% %6.2f%% %6.2f%% %6.2f%% %6.2f%%  %s  %08" PRIx64 "  %s \"%s\"\n", rep.ip.ToString().c_str(), rep.fGood && rep.blocks>0 && rep.clientVersion>0 && strlen(rep.clientSubVersion.c_str())>0?1:0, rep.lastSuccess, 100.0*rep.uptime[0], 100.0*rep.uptime[1], 100.0*rep.uptime[2], 100.0*rep.uptime[3], 100.0*rep.uptime[4], rep.blocks<1?"Unknown":blockbuffer, rep.services, rep.clientVersion<1?"Unknown":cversionbuffer, strlen(rep.clientSubVersion.c_str())==0?"Unknown":rep.clientSubVersion.c_str());
		} else
			fprintf(d, "%-47s  %4d  %11" PRId64 "  %6.2f%% %6.2f%% %6.2f%% %6.2f%% %6.2f%%  %6i  %08" PRIx64 "  %5i \"%s\"\n", rep.ip.ToString().c_str(), (int)rep.fGood, rep.lastSuccess, 100.0*rep.uptime[0], 100.0*rep.uptime[1], 100.0*rep.uptime[2], 100.0*rep.uptime[3], 100.0*rep.uptime[4], rep.blocks, rep.services, rep.clientVersion, rep.clientSubVersion.c_str());

        stat[0] += rep.uptime[0];
        stat[1] += rep.uptime[1];
        stat[2] += rep.uptime[2];
        stat[3] += rep.uptime[3];
        stat[4] += rep.uptime[4];
      }
      fclose(d);
      
	  ostringstream osLog;
	  osLog << "/usr/local/sDNS." << *coinNames[MainThreadNumber] << "/dnsstats.log";
	  
      FILE *ff = fopen(osLog.str().c_str(), "a");
      fprintf(ff, "%llu %g %g %g %g %g\n", (unsigned long long)(time(NULL)), stat[0], stat[1], stat[2], stat[3], stat[4]);
      fclose(ff);
      }}
	
	pthread_mutex_unlock(&mutex_mainthreadnumber);
  } while(1);
  return nullptr;
}


extern "C" void* ThreadStats(void* _MainThreadNumber) {
	
  int MainThreadNumber = 0;//*(int*)_MainThreadNumber;
  bool first = true;
  Sleep(3000);
  do {
	  MainThreadNumber = (MainThreadNumber+1)%actualMainThreadCount;
	/*if(MainThreadNumber != 2)
	{
		Sleep(1000);
		continue;
	}*/
	
	  //pthread_mutex_lock(&mutex_mainthreadnumber3);
	  //TempMainThreadNumber = MainThreadNumber;
	  
	  
    char c[256];
    time_t tim = time(NULL);
    struct tm *tmp = localtime(&tim);
    strftime(c, 256, "[%y-%m-%d %H:%M:%S]", tmp);
    CAddrDbStats stats;
	
	//pthread_mutex_unlock(&mutex_mainthreadnumber3);
	  

    db[MainThreadNumber].GetStats(stats);
	
	
	//pthread_mutex_lock(&mutex_mainthreadnumber3);
	
	  //TempMainThreadNumber = MainThreadNumber;
//    if (first)
//    {
//      first = false;
//	 // https://notes.burke.libbey.me/ansi-escape-codes/
//      printf("\n\n\n\x1b[3A"); // ANSI escape \x1b = ESC; 3A = move cursor up 3 c    hars
//    }
//    else
//      printf("\x1b[2K\x1b[u");  // u = restore cursor to position last saved by s
//    printf("\x1b[s"); // s = save cursor position
    uint64_t requests = 0;
    uint64_t queries = 0;
    for (unsigned int i=0; i<dnsThread[MainThreadNumber].size(); i++) {
      requests += dnsThread[MainThreadNumber][i]->dns_opt.nRequests;
      queries += dnsThread[MainThreadNumber][i]->dbQueries;
    }
	
	move(4, 0);          // move to begining of line
	clrtoeol();          // clear line
	move(8+MainThreadNumber, 0);          // move to begining of line
	clrtoeol();          // clear line
	//move(2, 0);          // move to begining of line
	//clrtoeol();          // clear line
	
	move(22+MainThreadNumber, 0);          // move to begining of line
	clrtoeol();          // clear line
	
    move(4,50); printw("%s",c);	// Date & Time
    move(4,72); printw("Total DNS  Requests: ----------  Threads: ---------- ");
    move(32,2); printw("Status:"); 

	/////////////////////////
	// Rows for each coin here:
	/////////////////////////

	if(coinNames[MainThreadNumber]){
		move(8+MainThreadNumber,2); printw("%s", coinNames[MainThreadNumber]->c_str());
	}
    move(8+MainThreadNumber,75);  printw("%i/%i", stats.nGood, stats.nAvail);			// Available
    move(8+MainThreadNumber,87);  printw("%i", stats.nTracked);					// tried
    move(8+MainThreadNumber,95);  printw("%i", stats.nAge);					// in sec : Age
    move(8+MainThreadNumber,106); printw("%i", stats.nNew);					// new
    move(8+MainThreadNumber,113); printw("%i", stats.nAvail - stats.nTracked - stats.nNew);	// active ( is a computed figure )
    move(8+MainThreadNumber,120); printw("%i", stats.nBanned);					// Banned
    move(8+MainThreadNumber,127); printw("%llu", (unsigned long long)requests);			// DNS Requests
    move(8+MainThreadNumber,135); printw("%llu", (unsigned long long)queries);			// db Queries

	if (fDNS[MainThreadNumber]) {
		// sub-Domain served
		move(8+MainThreadNumber,9);	 
		printw("%s", 
			string(host[MainThreadNumber]).substr(0, 24).c_str()/*, nPort[MainThreadNumber]*/);
		// Name Server
		move(8+MainThreadNumber,34);	 
		printw("%s", 
			string(ns[MainThreadNumber]).substr(0, 27).c_str()/*, nPort[MainThreadNumber]*/);
		// IP served from	
		move(8+MainThreadNumber,58);	 
		printw("%s", 
			string(ip_addr[MainThreadNumber]).substr(0, 15).c_str()/*, nPort[MainThreadNumber]*/);

		move(8+MainThreadNumber,143); printw("%i", nDnsThreads[MainThreadNumber]); // DNS Server Threads
	}
	move(8+MainThreadNumber,147); printw("%i", nThreads[MainThreadNumber]); // Crawler Threads
	move(8+MainThreadNumber,154); printw("Y");
    // printf("%s %i/%i available (%i tried in %is, %i new, %i active), %i banned; %llu DNS requests, %llu db queries", c, stats.nGood, stats.nAvail, stats.nTracked, stats.nAge, stats.nNew, stats.nAvail - stats.nTracked - stats.nNew, stats.nBanned, (unsigned long long)requests, (unsigned long long)queries);
    
	
	move(2,43);   printw("Multiple BlockChain   Node Tracker / DNS Seeder   Monitor    -    "); move(2,114);  printw("%s",dnsseeder_version);
	//move(2,48);   printw("Multiple BlockChain   Node Tracker / DNS Seeder   Monitor    -    v0.1.1.0.c\n");
	move(5,144); printw("Threads");

	// Section 1 - Label Fields
	move(5,127); printw("DNS     db");
	move(6,2);   printw("Coin   Host / Sub-Domain        Server Name             IP               Available   tried   in sec     new    Active Banned Request Queries DNS Crawl On");
	move(7,2);   printw("-----  ------------------------ ----------------------- ---------------  ----------- ------- ---------- ------ ------ ------ ------- ------- --- ----- --");
					   
	//move(7-1,89+25); printw("startd");
	//move(7-1/*+2*MainThreadNumber*/,78+25); printw("DNS");
	//move(7-1/*+2*MainThreadNumber*/,83+25); printw("Crawl");
	
	
	// Section 2, URL   & Block Height Status - Label Fields
	move(19,85); printw("Block Height");
	move(20,2);   printw("Coin   URL                                                                           Accept               Supported Whitelist Filters ");
	move(21,2);   printw("-----  ----------------------------------------------------------------------------  --------- ----------------------------------------------------");
      //move(21,2);   printw("-----  ----------------------------------------------------------------------------  --------- ---------  ----------------------------------------------------");
	
	
	// Section 2, URL   & Block Height Status - Update Rows
	if(coinNames[MainThreadNumber]){
		// 	Ticker
		move(22+MainThreadNumber,2); printw("%s", coinNames[MainThreadNumber]->c_str());
	}
	/*if (cfg_explorer_url[MainThreadNumber].empty()) {*/
		move(22+MainThreadNumber,87); 				// Default Acceptable BlockHeight
		printw("%d", nDefaultBlockHeight[MainThreadNumber]);

		// No appreciable difference ...., so remove "High Seen"
		//move(22+MainThreadNumber,97);
		//printw("%lld", nMaxBlockHeight[MainThreadNumber]); 	// Should be Highest BlockHeight Seen so far for this blockchain / coin

		//cout << "Will accept nodes reporting blockheight at or above: " << nDefaultBlockHeight << endl;
	/*} else {
		move(22+MainThreadNumber,83);
		printw("Will");// provide current blockheight info.");
		//cout << "Will seek current blockheight info from: " << cfg_explorer_url << endl;
	}*/
	
	  move(22,97);	// Supported White List Filters
	  for (std::set<uint64_t>::const_iterator it = opts.filter_whitelist.begin(); it != opts.filter_whitelist.end(); it++) 
	  {
		  if (it != opts.filter_whitelist.begin()) {
			printw(",");
		   // printf(",");
		  }
	 
		  printw("0x%lx", (unsigned long)*it);
		  //printf("0x%lx", (unsigned long)*it);
	  }
	  
	
	  move(22+MainThreadNumber,9);
	  if(coinNames[MainThreadNumber]){ // if the thread exist and running
		  if (!cfg_explorer_url[MainThreadNumber].empty()) {
			  printw("%s", &cfg_explorer_url[MainThreadNumber][0]);		// URL from which to obtain accept threshold blockheight for visited nodes.
			  //cerr << cfg_explorer_url << "// debug info"  << endl;
			  //cout << "Explorer: " << cfg_explorer_url << "\n";
		   } else {
			  printw("n/a");
			  //cout << "Explorer URL not set.\n";
		  }
	  }
	  
	  
	
	
	  refresh();
	
	  //pthread_mutex_unlock(&mutex_mainthreadnumber3);
    Sleep(400);
  } while(1);
  return nullptr;
}



// MultiSeeder / SuperSeeder: Vectorize Array sSeeds 
/// cameron:/usr/local/src/bitmark-seeder.dbkeys/main.cpp 424:5  
////  These should be regular P2P coin nodes which serve as "fixed seed nodes", 
//static const string mainnet_seeds[] =  {"seed.bitmark.co",
//                                        "de.bitmark.co",
//                                        "us.bitmark.co",
//                                        "eu.bitmark.io",
//                                        "ge.bitmark.io",
//                                        "jp.bitmark.io",
//                                        "mx.bitmark.io",
//                                        "us.bitmark.io",
//                                        "uk.bitmark.one",
//                                        ""};
//
//// Bitcoin Examples
////static const string mainnet_seeds[] = {"dnsseed.bluematt.me", "bitseed.xf2.org", "dnsseed.bitcoin.dashjr.org", "seed.bitcoin.sipa.be", ""};
//
//// Bitmark (MARKS) (BTM)  
//static const string testnet_seeds[] = { "tz.bitmark.co",
//                                        "tz.bitmark.guru",
//                                        "tz.bitmark.io",
//                                        "tz.bitmark.mx",
//                                        "tz.bitmark.one",
//                                       ""};
//// Bitcoin Examples
////static const string testnet_seeds[] = {"testnet-seed.alexykot.me",
////                                       "testnet-seed.bitcoin.petertodd.org",
////                                       "testnet-seed.bluematt.me",
////                                       "testnet-seed.bitcoin.schildbach.de",
////                                       ""};
//static const string *seeds = mainnet_seeds;

extern "C" void* ThreadSeeder(void* /*_MainThreadNumber*/) {
	
  //int MainThreadNumber = *(int*)_MainThreadNumber;
  // Bitmark - no TOR / Onion hidden service nodes yet; Nov. 29, 2020
  //if (!fTestNet){
  //  db.Add(CService("kjy2eqzk4zwi5zd3.onion", 8333), true);
  // }
  do {
	  for(int MainThreadNumber=0; MainThreadNumber<actualMainThreadCount; MainThreadNumber++)
	  {
		pthread_mutex_lock(&mutex_mainthreadnumber);
		TempMainThreadNumber = MainThreadNumber;
		for (int i=0; seeds[MainThreadNumber][i].compare(""); i++) {
			vector<CNetAddr> ips;
			LookupHost(seeds[MainThreadNumber][i].c_str(), ips);//within netbase.cpp (there's some globals there, may need to be multiplexed for each mainthread)
			for (vector<CNetAddr>::iterator it = ips.begin(); it != ips.end(); it++) {
				db[MainThreadNumber].Add(CService(*it, cfg_wallet_port[MainThreadNumber]), true);
			}
		}
		pthread_mutex_unlock(&mutex_mainthreadnumber);
	  }
	Sleep(1800000);
  } while(1);
  return nullptr;
}

  
extern "C" void* MainThread(void* arg) {

  int MainThreadNumber = *(int *)arg;
  
  pthread_mutex_lock(&mutex_mainthreadnumber);
  TempMainThreadNumber = MainThreadNumber;
  //if(MainThreadNumber == 1)
//	  return nullptr;
  //fprintf(stderr, "MainThreadNumber=%d\n", MainThreadNumber);
  
  
  Config cfg;
  /*ostringstream os;
  os << "settings" << MainThreadNumber << ".conf";
  string sConfigName = os.str();*/
  
  if(!configPaths[MainThreadNumber]){
	  move(8+MainThreadNumber,8);  printw("no config");
	  return nullptr;
  }
  
  
  // Read "settings.conf" file for configuration parameters.
  try {
    cfg.readFile(configPaths[MainThreadNumber]->c_str());
  } catch(const FileIOException &fioex) {
    std::cerr << "Error: cannot open " + (*configPaths[MainThreadNumber]) << std::endl;
    return nullptr;//(EXIT_FAILURE);
  } catch(const ParseException &pex) {
    std::cerr << "Parse error at " << pex.getFile() << ":" << pex.getLine()
              << " - " << pex.getError() << std::endl;
    return nullptr;//(EXIT_FAILURE);
  }


  
	try {
		const char* tmp = cfg.lookup("ip_addr").c_str();
		const char* ip4_addr;
		
		if (strchr(tmp, ':') != nullptr) {
            char* ip4_addr = (char*) malloc(strlen(tmp)+8);
            strcpy(ip4_addr, "::FFFF:");
            strcat(ip4_addr, tmp);
            ip_addr[MainThreadNumber] = ip4_addr;
          } else {
            ip_addr[MainThreadNumber] = tmp;
          }
  } catch(const SettingNotFoundException &nfex) {
    //cerr << "" << endl;
	ip_addr[MainThreadNumber] = "::";
  }

 
  
  try {
		//printf("ns[MainThreadNumber] read\n");
    ns[MainThreadNumber] = cfg.lookup("ns").c_str();
	//printf("ns[MainThreadNumber]: %s\n", ns[MainThreadNumber]);
	if(ns[MainThreadNumber][0] == 0){
		//printf("ns[MainThreadNumber]: null\n");
		ns[MainThreadNumber] = nullptr;
	}
  } catch(const SettingNotFoundException &nfex) {
    //cerr << "" << endl;
	ns[MainThreadNumber] = nullptr;
  }

  try {
    host[MainThreadNumber] = cfg.lookup("host").c_str();
	if(host[MainThreadNumber][0] == 0)
		host[MainThreadNumber] = nullptr;
  } catch(const SettingNotFoundException &nfex) {
    //cerr << "" << endl;
	host[MainThreadNumber] = nullptr;
  }

  try {
    mbox[MainThreadNumber] = cfg.lookup("mbox").c_str();
	if(mbox[MainThreadNumber][0] == 0)
		mbox[MainThreadNumber] = nullptr;
  } catch(const SettingNotFoundException &nfex) {
    //cerr << "" << endl;
	mbox[MainThreadNumber] = nullptr;
  }

// nThreads(96), nDnsThreads(4), ip_addr("::"), nPort(53)
  try {
    nThreads[MainThreadNumber] = std::stoi(cfg.lookup("nThreads").c_str());
  } catch(const SettingNotFoundException &nfex) {
    //cerr << "" << endl;
	nThreads[MainThreadNumber] = 96;
  }

  
  try {
    nPort[MainThreadNumber] = std::stoi(cfg.lookup("nPort").c_str());
  } catch(const SettingNotFoundException &nfex) {
    //cerr << "" << endl;
	nPort[MainThreadNumber] = 53;
  }

  try {
    nDnsThreads[MainThreadNumber] = std::stoi(cfg.lookup("nDnsThreads").c_str());
  } catch(const SettingNotFoundException &nfex) {
    //cerr << "" << endl;
    nDnsThreads[MainThreadNumber] = 4;
  }

  if (!ns[MainThreadNumber]) {
    move(32+MainThreadNumber,8); //  to warning window ?
    printw("No nameserver set. Not starting DNS server.\n");
    //printf("No nameserver set. Not starting DNS server.\n");
    fDNS[MainThreadNumber] = false;
  }
  else{
	  fDNS[MainThreadNumber] = true;
  }
  if (fDNS[MainThreadNumber] && !host[MainThreadNumber]) {
	move(32+MainThreadNumber,8); //  to warning window ?
    fprintf(stderr, "No hostname set. Please use -h.\n");
    exit(1);
  }
  if (mbox[MainThreadNumber] == NULL) {
    // No email set. Initialize to "" string
    mbox[MainThreadNumber] = "";
  } else {
    // Email is set. Replace "@" with "."
    mbox[MainThreadNumber] = charReplace(mbox[MainThreadNumber], '@', '.');
  }

  
  // This version introduces "BlockChain Name" parameter 
  try {
    cfg_blockchain_name[MainThreadNumber] = cfg.lookup("blockchain_name").c_str();
    // cout << cfg_blockchain_name << " -  DNS Seed Server - " << sAppName << " v" << sAppVersion << "\n";
  } catch(const SettingNotFoundException &nfex) {
        // return(EXIT_FAILURE); // Too drastic: can ignore this failure
        cout << "Missing 'blockchain_name' setting in configuration file." << endl;
        cout << "Please set blockchain_name=\"<name>\" parameter in 'settings.conf' file\n";
  }
 
  
  try {
    cfg_protocol_version[MainThreadNumber] = std::stoi(cfg.lookup("protocol_version").c_str());
  } catch(const SettingNotFoundException &nfex) {
    cerr << "Error: Missing 'protocol_version' setting in configuration file." << endl;
	return nullptr;//(EXIT_FAILURE);
  }

  try {
    cfg_init_proto_version[MainThreadNumber] = std::stoi(cfg.lookup("init_proto_version").c_str());
  } catch(const SettingNotFoundException &nfex) {
    cerr << "Error: Missing 'init_proto_version' setting in configuration file." << endl;
	return nullptr;//(EXIT_FAILURE);
  }

  
  try {
    cfg_min_peer_proto_version[MainThreadNumber] = std::stoi(cfg.lookup("min_peer_proto_version").c_str());
  } catch(const SettingNotFoundException &nfex) {
    // If the value is not properly set, then default min_peer_proto_version to the protocol_version
    cfg_min_peer_proto_version[MainThreadNumber] = cfg_protocol_version[MainThreadNumber];
  }

  try {
    cfg_caddr_time_version[MainThreadNumber] = std::stoi(cfg.lookup("caddr_time_version").c_str());
  } catch(const SettingNotFoundException &nfex) {
    cerr << "Error: Missing 'caddr_time_version' setting in configuration file." << endl;
	return nullptr;//(EXIT_FAILURE);
  }

  for (int i=0; i<4; i++) {
	  try {
        cfg_message_start[MainThreadNumber][i] = static_cast<char>(hex_string_to_int(cfg.lookup("pchMessageStart_" + std::to_string(i)).c_str()));
	  } catch(const SettingNotFoundException &nfex) {
		cerr << "Error: Missing 'pchMessageStart_" + std::to_string(i) + "' setting in configuration file." << endl;
		return nullptr;//(EXIT_FAILURE);
	  }
  }

  
  try {
    cfg_wallet_port[MainThreadNumber] = std::stoi(cfg.lookup("wallet_port").c_str());
  } catch(const SettingNotFoundException &nfex) {
    cerr << "Error: Missing 'wallet_port' setting in configuration file. (ie., this blockchain's standard P2P port)" << endl;
	return nullptr;//(EXIT_FAILURE);
  }
  
  try {
    cfg_explorer_url[MainThreadNumber] = cfg.lookup("explorer_url").c_str();
	//printf("EXPLORER URL: %s \n",&cfg_explorer_url[0]);
	//cout << "EXPLORER URL: " << cfg_explorer_url;
	//cin >> cfg_explorer_url2;
  } catch(const SettingNotFoundException &nfex) {
    cfg_explorer_url[MainThreadNumber] = "";
  }
  
  
  try {
    cfg_explorer_url2[MainThreadNumber] = cfg.lookup("second_explorer_url").c_str();
	if (cfg_explorer_url2[MainThreadNumber].compare("") && cfg_explorer_url[MainThreadNumber].compare("") == 0) {
		cfg_explorer_url[MainThreadNumber] = cfg_explorer_url2[MainThreadNumber];
		cfg_explorer_url2[MainThreadNumber] = "";
	}
  } catch(const SettingNotFoundException &nfex) {
	  cfg_explorer_url2[MainThreadNumber] = "";
  }  


  try {
      if (is_numeric(const_cast<char*>(cfg.lookup("explorer_requery_seconds").c_str()))) {
          cfg_explorer_requery_seconds[MainThreadNumber] = std::stoi(cfg.lookup("explorer_requery_seconds").c_str());
          if (cfg_explorer_requery_seconds[MainThreadNumber] < 1) {
              cerr << "Error: 'explorer_requery_seconds' setting must be greater than zero." << endl;
              return nullptr;//(EXIT_FAILURE);
          }
      } else {
          // Default to 60 seconds
          cfg_explorer_requery_seconds[MainThreadNumber] = 60;
      }
  } catch(const SettingNotFoundException &nfex) {
    if (cfg_explorer_url[MainThreadNumber].compare("") || cfg_explorer_url2[MainThreadNumber].compare("")) {
      cerr << "Error: Missing 'explorer_requery_seconds' setting in configuration file." << endl;
      return nullptr;//(EXIT_FAILURE);
    } else {
      cfg_explorer_requery_seconds[MainThreadNumber] = 0;
    }
  }

  
  try {
	nDefaultBlockHeight[MainThreadNumber] = std::stoi(cfg.lookup("block_count").c_str());
	nCurrentBlock[MainThreadNumber] = nDefaultBlockHeight[MainThreadNumber];
  } catch(const SettingNotFoundException &nfex) {
    cerr << "Error: Missing 'block_count' setting in configuration file." << endl;
	return nullptr;//(EXIT_FAILURE);
  }

  for (int i=1; i<=10; i++) {
	  try {
		sSeeds[MainThreadNumber][i-1] = cfg.lookup("seed_" + std::to_string(i)).c_str();
	  } catch(const SettingNotFoundException &nfex) {
		cerr << "Error: Missing 'seed_0" + std::to_string(i) + "' setting in configuration file." << endl;
		return nullptr;//(EXIT_FAILURE);
	  }
  }

  signal(SIGPIPE, SIG_IGN);
  setbuf(stdout, NULL);
  
  
  
  
  ostringstream os2;
  os2 << "/usr/local/sDNS." << *coinNames[MainThreadNumber] << "/dnsseed.dat";
  FILE *f = fopen(os2.str().c_str(),"r");
  if (f) {
    //printf("Loading dnsseed.dat... %s\n", os2.str().c_str());
	TempMainThreadNumber = MainThreadNumber;
    CAutoFile cf(f);
    cf >> db[MainThreadNumber];
    if (opts.fWipeBan)
        db[MainThreadNumber].banned.clear();
    if (opts.fWipeIgnore)
        db[MainThreadNumber].ResetIgnores();

    ///printf("done\n");
  }else{
	  move(32,10);				// move(y,x)
	  printw("%s, db not loaded!",coinNames[MainThreadNumber]);
	  //printf("db not loaded!\n\r");
	  //exit(1);
     if (opts.fWipeBan)
	         db[MainThreadNumber].banned.clear();
     if (opts.fWipeIgnore)
	         db[MainThreadNumber].ResetIgnores();
  }
  
  pthread_mutex_unlock(&mutex_mainthreadnumber);
  
  
  fDumpAll = opts.fDumpAll;
  //if(MainThreadNumber == 0)
	//  return nullptr;
  sForceIP.assign(opts.force_ip, strlen(opts.force_ip));
  
  
  
  pthread_t threadBlock, threadDump;
  ///printf("Starting block reader...");
  pthread_create(&threadBlock, NULL, ThreadBlockReader, &MainThreadNumber);
  ///printf("done\n");
  
  
  pthread_t *threadDns=new pthread_t[nDnsThreads[MainThreadNumber]];
	
  if (fDNS) {
    //move(4/*+2*MainThreadNumber*/,6);	 printw("%s on %s:%i", opts.host, opts.ns, opts.nPort);
    //printf("Starting %i DNS threads for %s on %s (port %i)...", opts.nDnsThreads, opts.host, opts.ns, opts.nPort);
    dnsThread[MainThreadNumber].clear();
    for (int i=0; i<nDnsThreads[MainThreadNumber]; i++) {
      dnsThread[MainThreadNumber].push_back(new CDnsThread(&opts, i, MainThreadNumber));
    }
	for (int i=0; i<nDnsThreads[MainThreadNumber]; i++) {
      pthread_create(&threadDns[i], NULL, ThreadDNS, dnsThread[MainThreadNumber][i]);
      Sleep(20);
	}
    //move(8+MainThreadNumber,81); printw("%i", opts.nDnsThreads);
    /// TODO REMOVED move(11/*+2*MainThreadNumber*/,29); printw("startd");
    //printf("done\n");
  }
  
  //move(8+MainThreadNumber,95); printw("Y");
  //printf("done\n");
  // TODO REMOVED move(13/*+2*MainThreadNumber*/,7); printw("crawler threads:");
  // TODO REMOVED move(13/*+2*MainThreadNumber*/,25); printw("%i", opts.nThreads);
  //printf("Starting %i crawler threads...", opts.nThreads);
  refresh();
  pthread_attr_t *attr_crawler=new pthread_attr_t[nThreads[MainThreadNumber]];
    pthread_t* thread = new pthread_t[nThreads[MainThreadNumber]];
	ThreadCrawlerArgs* tArgs = new ThreadCrawlerArgs[nThreads[MainThreadNumber]];
  for (int i=0; i<nThreads[MainThreadNumber]; i++) {
	  
	pthread_attr_init(&attr_crawler[i]);
	pthread_attr_setstacksize(&attr_crawler[i], 0x20000);
  
	tArgs[i].nThreads = nThreads[MainThreadNumber];
	tArgs[i].MainThreadNumber = MainThreadNumber;
    pthread_create(&thread[i], &attr_crawler[i], ThreadCrawler, &tArgs[i]);
  
	pthread_attr_destroy(&attr_crawler[i]);
  }
  //move(8+MainThreadNumber,85); printw("%i", opts.nThreads);
  //printf("done\n");

//  cout << "\n   " << cfg_blockchain_name << " -  DNS Seed Server\n";
//  cout << "\t for sub-domain: " << opts.host << endl;
//  cout << "\t ( Query with: \'dig -p " << opts.nPort << " @" << opts.ns << " " << opts.host <<"\' )\n" << endl;


  
  pthread_create(&threadDump, NULL, ThreadDumper, &MainThreadNumber);
  void* res;
  pthread_join(threadDump, &res);
  
  
  return nullptr;
}



int main(int argc, char **argv) {
	for(int i=0; i<SEEDER_COUNT; i++)
		seeds[i] = sSeeds[i];
	
  
  
  //printf("%s\n", (sAppName + " v" + sAppVersion).c_str());

    if (pthread_mutex_init(&mutex_mainthreadnumber, NULL) != 0) {
        printf("\n mutex init has failed\n");
        return 1;
    }
    /*if (pthread_mutex_init(&mutex_mainthreadnumber2, NULL) != 0) {
        printf("\n mutex init has failed\n");
        return 1;
    }
    if (pthread_mutex_init(&mutex_mainthreadnumber3, NULL) != 0) {
        printf("\n mutex init has failed\n");
        return 1;
    }
    if (pthread_mutex_init(&mutex_mainthreadnumber4, NULL) != 0) {
        printf("\n mutex init has failed\n");
        return 1;
    }
    if (pthread_mutex_init(&mutex_mainthreadnumberCrawlerTestNode, NULL) != 0) {
        printf("\n mutex init has failed\n");
        return 1;
    }*/
	
	
  
  opts.ParseCommandLine(argc, argv); //  Check for command line arguments
  
  
  initscr();
  
  
  
  ///printf("Supporting whitelisted filters: ");
  /*move(16,15);
  for (std::set<uint64_t>::const_iterator it = opts.filter_whitelist.begin(); it != opts.filter_whitelist.end(); it++) {
      if (it != opts.filter_whitelist.begin()) {
	  printw(",");
       // printf(",");
      }
 
      printw("0x%lx", (unsigned long)*it);
      //printf("0x%lx", (unsigned long)*it);
  }
  printw("\n");*/
  //printf("\n");
  if (opts.tor) {
    CService service(opts.tor, 9050);
    if (service.IsValid()) {
      printw("Using Tor proxy at %s\n", service.ToStringIPPort().c_str());
      //printf("Using Tor proxy at %s\n", service.ToStringIPPort().c_str());
      SetProxy(NET_TOR, service);
    }
  }
  if (opts.ipv4_proxy) {
    CService service(opts.ipv4_proxy, 9050);
    if (service.IsValid()) {
      printw("Using IPv4 proxy at %s\n", service.ToStringIPPort().c_str());
      //printf("Using IPv4 proxy at %s\n", service.ToStringIPPort().c_str());
      SetProxy(NET_IPV4, service);
    }
  }
  if (opts.ipv6_proxy) {
    CService service(opts.ipv6_proxy, 9050);
    if (service.IsValid()) {
      printw("Using IPv6 proxy at %s\n", service.ToStringIPPort().c_str());
      //printf("Using IPv6 proxy at %s\n", service.ToStringIPPort().c_str());
      SetProxy(NET_IPV6, service);
    }
  }
  if (strcmp(opts.force_ip, "A") != 0 && strcmp(opts.force_ip, "a") != 0 && strcmp(opts.force_ip, "4") != 0 && strcmp(opts.force_ip, "6") != 0) {
    fprintf(stderr, "Invalid force ip option. Valid options are: a = all (default), 4 = IPv4, 6 = IPv6.\n");
    exit(1);
  }
  
  void* res;
  
  // Scan  /usr/local  for  sDNS.<COIN>  directories 
  string dir_path = "/usr/local/";
  DIR *d;
  struct dirent *dir;
  d = opendir(dir_path.c_str());
	
  int i=0;
  if (d) {
    while ((dir = readdir(d)) != NULL /*&& i<4*/) {
	  if(strlen(dir->d_name) < 4)
		  continue;
	  if(strncmp(dir->d_name, "sDNS", 4) == 0)
	  {
		  configPaths[i] = new string(dir_path);
		  configPaths[i]->append(dir->d_name);
		  configPaths[i]->append("/settings.conf");
		  // printf("%s\n\r", configPaths[i]->c_str());
		  // Ticker symbols are extracted from /usr/local/sDNS.<TICK> directories 
		  coinNames[i] = new string((char*)&(dir->d_name[5]));//ignore the first 5 character including the '.'
		  i++;
	  }
    }
    closedir(d);
  }

  actualMainThreadCount = i;
  pthread_t mainThread[SEEDER_COUNT];
  pthread_attr_t attr_main[SEEDER_COUNT];
  int MainThreadNumber[SEEDER_COUNT];
    
    pthread_t threadStats, threadSeed;
    //printf("Starting seeder...");
    pthread_create(&threadSeed, NULL, ThreadSeeder, /*&MainThreadNumber*/nullptr);


  for(int j=0; j<actualMainThreadCount; j++)
  {
	  pthread_attr_init(&attr_main[j]);
	  pthread_attr_setstacksize(&attr_main[j], 0x20000);
	  MainThreadNumber[j] = j;
	  pthread_create(&mainThread[j], &attr_main[j], MainThread, &MainThreadNumber[j]);
	  //cout << j << endl;
  }
  
  
  
  
  
  //below should run after main threads send sig pipe
  
//  pthread_t threadStats, threadSeed;
  pthread_create(&threadStats, NULL, ThreadStats, /*&MainThreadNumber*/nullptr);
  //printf("Starting seeder...");
//  pthread_create(&threadSeed, NULL, ThreadSeeder, /*&MainThreadNumber*/nullptr);
  
  for(int j=0; j<actualMainThreadCount; j++)
	pthread_join(mainThread[j], &res);
  
  endwin();
  return 0;
}
