#include <algorithm>

#include <pthread.h>

#include "db.h"
#include "netbase.h"
#include "protocol.h"
#include "serialize.h"
#include "uint256.h"

#define BITCOIN_SEED_NONCE  0x0539a019ca550825ULL

using namespace std;

extern pthread_mutex_t mutex_mainthreadnumber;

//extern int TempMainThreadNumber;

class CNode {
  SOCKET sock;
  CDataStream vSend;
  CDataStream vRecv;
  unsigned int nHeaderStart;
  unsigned int nMessageStart;
  int nVersion;
  string strSubVer;
  int nStartingHeight;
  vector<CAddress> *vAddr;
  int ban;
  int64 doneAfter;
  CAddress you;

  int GetTimeout() {
      if (you.IsTor())
          return 120;
      else
          return 30;
  }

  void BeginMessage(const char *pszCommand) {
    if (nHeaderStart != -1) AbortMessage();
    nHeaderStart = vSend.size();
    vSend << CMessageHeader(pszCommand, 0);
    nMessageStart = vSend.size();
//    printf("%s: SEND %s\n", ToString(you).c_str(), pszCommand); 
  }
  
  void AbortMessage() {
    if (nHeaderStart == -1) return;
    vSend.resize(nHeaderStart);
    nHeaderStart = -1;
    nMessageStart = -1;
  }
  
  void EndMessage() {
    if (nHeaderStart == -1) return;
    unsigned int nSize = vSend.size() - nMessageStart;
    memcpy((char*)&vSend[nHeaderStart] + offsetof(CMessageHeader, nMessageSize), &nSize, sizeof(nSize));
    uint256 hash = Hash(vSend.begin() + nMessageStart, vSend.end());
    unsigned int nChecksum = 0;
    memcpy(&nChecksum, &hash, sizeof(nChecksum));
    assert(nMessageStart - nHeaderStart >= offsetof(CMessageHeader, nChecksum) + sizeof(nChecksum));
    memcpy((char*)&vSend[nHeaderStart] + offsetof(CMessageHeader, nChecksum), &nChecksum, sizeof(nChecksum));
    nHeaderStart = -1;
    nMessageStart = -1;
  }
  
  void Send() {
    if (sock == INVALID_SOCKET) {printf("Send():invsock\n");return;}
    if (vSend.empty()) return;
    int nBytes = send(sock, &vSend[0], vSend.size(), 0);
    if (nBytes > 0) {
      vSend.erase(vSend.begin(), vSend.begin() + nBytes);
    } else {
		printf("Send():else\n");
      close(sock);
      sock = INVALID_SOCKET;
    }
  }
 
  void PushVersion(int _TempMainThreadNumber) {
    int64 nTime = time(NULL);
    uint64 nLocalNonce = BITCOIN_SEED_NONCE;
    int64 nLocalServices = 0;
    CAddress me(CService("0.0.0.0"));
    BeginMessage("version");
    string ver = "/" + sAppName + "/";
    uint8_t fRelayTxs = 0;
	//printf("nCurrentBlock[TempMainThreadNumber]:%d\n", nCurrentBlock[TempMainThreadNumber]);
    vSend << cfg_protocol_version[_TempMainThreadNumber] << nLocalServices << nTime << you << me << nLocalNonce << ver << nCurrentBlock[_TempMainThreadNumber] << fRelayTxs;
    EndMessage();
  }
 
  void GotVersion() {
    // printf("\n%s: version %i\n", ToString(you).c_str(), nVersion);
    if (vAddr) {
      BeginMessage("getaddr");
      EndMessage();
      doneAfter = time(NULL) + GetTimeout();
    } else {
      doneAfter = time(NULL) + 1;
    }
  }

  bool ProcessMessage(int _TempMainThreadNumber, string strCommand, CDataStream& vRecv) {
//    printf("%s: RECV %s\n", ToString(you).c_str(), strCommand.c_str());
    if (strCommand == "version") {
      int64 nTime;
      CAddress addrMe;
      CAddress addrFrom;
      uint64 nNonce = 1;
      vRecv >> nVersion >> you.nServices >> nTime >> addrMe;
      if (!vRecv.empty())
        vRecv >> addrFrom >> nNonce;
      if (!vRecv.empty())
        vRecv >> strSubVer;
      if (!vRecv.empty())
        vRecv >> nStartingHeight;
      // Change version
      BeginMessage("verack");
      EndMessage();
      vSend.SetVersion(min(nVersion, cfg_protocol_version[_TempMainThreadNumber]));
      return false;
    }
    
    if (strCommand == "verack") {
      this->vRecv.SetVersion(min(nVersion, cfg_protocol_version[_TempMainThreadNumber]));
      GotVersion();
      return false;
    }
    
    if (strCommand == "addr" && vAddr) {
      vector<CAddress> vAddrNew;
      vRecv >> vAddrNew;
      // printf("%s: got %i addresses\n", ToString(you).c_str(), (int)vAddrNew.size());
      int64 now = time(NULL);
      vector<CAddress>::iterator it = vAddrNew.begin();
      if (vAddrNew.size() > 1) {
        if (doneAfter == 0 || doneAfter > now + 1) doneAfter = now + 1;
      }
      while (it != vAddrNew.end()) {
        CAddress &addr = *it;
//        printf("%s: got address %s\n", ToString(you).c_str(), addr.ToString().c_str(), (int)(vAddr->size()));
        it++;
        if (addr.nTime <= 100000000 || addr.nTime > now + 600)
          addr.nTime = now - 5 * 86400;
        if (addr.nTime > now - 604800)
          vAddr->push_back(addr);
//        printf("%s: added address %s (#%i)\n", ToString(you).c_str(), addr.ToString().c_str(), (int)(vAddr->size()));
        if (vAddr->size() > 1000) {doneAfter = 1; return true; }
      }
      return false;
    }
    
    return false;
  }
  
  bool ProcessMessages(int _TempMainThreadNumber) {
    if (vRecv.empty()) return false;
    do {
        pthread_mutex_lock(&mutex_mainthreadnumber);
        TempMainThreadNumber = _TempMainThreadNumber;
      
      CDataStream::iterator pstart = search(vRecv.begin(), vRecv.end(), BEGIN(cfg_message_start[_TempMainThreadNumber]), END(cfg_message_start[_TempMainThreadNumber]));
      int nHeaderSize = vRecv.GetSerializeSize(CMessageHeader());
      if (vRecv.end() - pstart < nHeaderSize) {
        if (vRecv.size() > nHeaderSize) {
          vRecv.erase(vRecv.begin(), vRecv.end() - nHeaderSize);
        }
        pthread_mutex_unlock(&mutex_mainthreadnumber);
        break;
      }
      vRecv.erase(vRecv.begin(), pstart);
      vector<char> vHeaderSave(vRecv.begin(), vRecv.begin() + nHeaderSize);
      TempMainThreadNumber = _TempMainThreadNumber;
      CMessageHeader hdr;
      vRecv >> hdr;
      if (!hdr.IsValid()) { 
        // printf("%s: BAD (invalid header)\n", ToString(you).c_str());
        ban = 100000; 

        pthread_mutex_unlock(&mutex_mainthreadnumber); 
        return true;
      }
      string strCommand = hdr.GetCommand();
      unsigned int nMessageSize = hdr.nMessageSize;
      if (nMessageSize > MAX_SIZE) { 
        // printf("%s: BAD (message too large)\n", ToString(you).c_str());
        ban = 100000;
        pthread_mutex_unlock(&mutex_mainthreadnumber);
        return true; 
      }
      if (nMessageSize > vRecv.size()) {
        vRecv.insert(vRecv.begin(), vHeaderSave.begin(), vHeaderSave.end());
        pthread_mutex_unlock(&mutex_mainthreadnumber);
        break;
      }
      // Checksum
      uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
      unsigned int nChecksum = 0;
      memcpy(&nChecksum, &hash, sizeof(nChecksum));
      if (nChecksum != hdr.nChecksum) {

          pthread_mutex_unlock(&mutex_mainthreadnumber);
          continue;
      }

      CDataStream vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.nType, vRecv.nVersion);
      vRecv.ignore(nMessageSize);
      if (ProcessMessage(_TempMainThreadNumber, strCommand, vMsg)){
          pthread_mutex_unlock(&mutex_mainthreadnumber);
        return true;
      }
      pthread_mutex_unlock(&mutex_mainthreadnumber);
//      printf("%s: done processing %s\n", ToString(you).c_str(), strCommand.c_str());
    } while(1);
    return false;
  }
  
public:
  CNode(int _TempMainThreadNumber, const CService& ip, vector<CAddress>* vAddrIn) : you(ip), nHeaderStart(-1), nMessageStart(-1), vAddr(vAddrIn), ban(0), doneAfter(0), nVersion(0) {
    vSend.SetType(SER_NETWORK);
    vSend.SetVersion(cfg_init_proto_version[_TempMainThreadNumber]);
    vRecv.SetType(SER_NETWORK);
    vRecv.SetVersion(cfg_init_proto_version[_TempMainThreadNumber]);
	//printf("cfg_init_proto_version[TempMainThreadNumber]:%d\n", cfg_init_proto_version[TempMainThreadNumber]);
  }
  bool Run(int _TempMainThreadNumber) {
    bool res = true;
    if (!ConnectSocket(you, sock)){                                             
		//printf("bitcoin.cpp Run socket cant connect\n");                    
		return false;                                                       
	}else{
		//printf("bitcoin.cpp Run socket CAN connect\n"); 
	}

    pthread_mutex_lock(&mutex_mainthreadnumber);
    TempMainThreadNumber = _TempMainThreadNumber;
    PushVersion(_TempMainThreadNumber);
    Send();
    pthread_mutex_unlock(&mutex_mainthreadnumber);

    int64 now;
	//Sleep(1000);
    now = time(NULL);
    //printf("doneAfter (%lld)-now: %lld\n", doneAfter, (doneAfter - now));
    while (now = time(NULL), ban == 0 && (doneAfter == 0 || doneAfter > now) && sock != INVALID_SOCKET) {
      char pchBuf[0x10000];
      fd_set read_set, except_set;
      FD_ZERO(&read_set);
      FD_ZERO(&except_set);
      FD_SET(sock,&read_set);
      FD_SET(sock,&except_set);
      struct timeval wa;
      if (doneAfter) {
        wa.tv_sec = doneAfter - now;
        wa.tv_usec = 0;
      } else {
        wa.tv_sec = GetTimeout();
        wa.tv_usec = 0;
      }
      int ret = select(sock+1, &read_set, NULL, &except_set, &wa);
      if (ret != 1) {
        if (!doneAfter) res = false;
		//printf("bitcoin.cpp::Run/res=false set\n");
        break;
      }
      int nBytes = recv(sock, pchBuf, sizeof(pchBuf), 0);


      pthread_mutex_lock(&mutex_mainthreadnumber);
      TempMainThreadNumber = _TempMainThreadNumber;
      int nPos = vRecv.size();
      if (nBytes > 0) {
        vRecv.resize(nPos + nBytes);
        memcpy(&vRecv[nPos], pchBuf, nBytes);
      } else if (nBytes == 0) {
         //printf("%s: BAD (connection closed prematurely)\n", ToString(you).c_str());
        res = false;
        pthread_mutex_unlock(&mutex_mainthreadnumber);
        break;
      } else {
         //printf("%s: BAD (connection error)\n", ToString(you).c_str());
        res = false;
        pthread_mutex_unlock(&mutex_mainthreadnumber);
        break;
      }
      pthread_mutex_unlock(&mutex_mainthreadnumber);


      ProcessMessages(_TempMainThreadNumber);// mutexed already

      pthread_mutex_lock(&mutex_mainthreadnumber);
      TempMainThreadNumber = _TempMainThreadNumber;
      Send();
      pthread_mutex_unlock(&mutex_mainthreadnumber);
    }
    if (sock == INVALID_SOCKET){ res = false;printf("bitcoincpp sock == INVALID_SOCKET\n");}
    close(sock);
    sock = INVALID_SOCKET;
    return (ban == 0) && res;
  }
  
  int GetBan() {
    return ban;
  }
  
  int GetClientVersion() {
    return nVersion;
  }
  
  std::string GetClientSubVersion() {
    return strSubVer;
  }
  
  int GetStartingHeight() {
    return nStartingHeight;
  }

  uint64_t GetServices() {
    return you.nServices;
  }
};

bool TestNode(int _TempMainThreadNumber, const CService &cip, int &ban, int &clientV, std::string &clientSV, int &blocks, bool &insync, vector<CAddress>* vAddr, uint64_t& services) {
  try {
    CNode node(_TempMainThreadNumber, cip, vAddr);
    bool ret = node.Run(_TempMainThreadNumber);
    if (!ret)
		ban = node.GetBan();
	else
		ban = 0;
    clientV = node.GetClientVersion();
    clientSV = node.GetClientSubVersion();
    blocks = node.GetStartingHeight();
    if (bCurrentBlockFromExplorer[_TempMainThreadNumber])
      insync = (blocks >= nCurrentBlock[_TempMainThreadNumber]-5 && blocks <= nCurrentBlock[_TempMainThreadNumber]+5);
    else
      insync = (blocks >= nCurrentBlock[_TempMainThreadNumber]);
    services = node.GetServices();
//  printf("%s: %s!!!\n", cip.ToString().c_str(), ret ? "GOOD" : "BAD");
    return ret;
  } catch(std::ios_base::failure& e) {
    ban = 0;
    return false;
  }
}
