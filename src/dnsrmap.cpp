#include "../include/dnsrmap.h"
#include <time.h>
#include <vector>
#include <map>
using namespace std;

#ifdef WIN32
#include <Windows.h>
#define MUTEX_T CRITICAL_SECTION
#define MUINIT(pMu) InitializeCriticalSection ( pMu)
#define MULOCK(pMu) EnterCriticalSection ( pMu)
#define MUUNLOCK(pMu) LeaveCriticalSection ( pMu)
#define in_addr_t ULONG

#else
#include <pthread.h>
#define MUTEX_T pthread_mutex_t
#define MUINIT(pMu) pthread_mutex_init ( (pMu), 0)
#define MULOCK(pMu) pthread_mutex_lock ( pMu)
#define MUUNLOCK(pMu) pthread_mutex_unlock ( pMu)

#endif // WIN32


#define CLEANUP_INTERVAL_SEC 60*15 // 15 minutes
#define OLD_ENTRY_SECONDS 60*10 // 20 minutes


class DnsAddrEntryImpl : public DnsAddrEntry
{
public:

  virtual std::string getName() const { return _name; }
  virtual std::string getPath() { return _path; }
  virtual bool        isV6() { return _isV6; }
  virtual in_addr     getAddr4() { return _addr4; }
  virtual in6_addr    getAddr6() { return _addr6; }
  virtual std::string getAddrStr() { return _addrStr; }

  DnsAddrEntryImpl(in_addr addr, std::string name, std::string path, std::string addrStr) : _name(name), _path(path), _isV6(false), _addrStr(addrStr), _tAddedSec(0)
  {
    _addr4 = addr;
  }
  DnsAddrEntryImpl(in6_addr addr, std::string name, std::string path, std::string addrStr) : _name(name), _path(path), _isV6(true), _addrStr(addrStr), _tAddedSec(0)
  {
    _addr6 = addr;
  }

  std::string _name;
  std::string _path;
  bool        _isV6;
  in_addr     _addr4;
  in6_addr    _addr6;
  std::string _addrStr;

  uint32_t    _tAddedSec; // optionally used by DnsRMap implementation to track and remove old entries

};



class DnsRMapImpl : public DnsRMap
{
public:
  DnsRMapImpl() : _mapAddr4(), _mapAddr6(), _tLastCleanup(0L) {
    MUINIT(&_mutex4);
    MUINIT(&_mutex6);
  }
  ~DnsRMapImpl() {
    _mapAddr4.clear();
    _mapAddr6.clear();
  }

  //------------------------------------------------------------------------
  // add  IPv4 address mapping
  //------------------------------------------------------------------------

  virtual void add(in_addr  addr, std::string name, std::string path, std::string addrStr)
  {
    time_t now = time(NULL);

    DnsAddrEntryImpl *entry = new DnsAddrEntryImpl(addr, name, path, addrStr);
    entry->_tAddedSec = now;

    CheckCleanup(now);

    MULOCK(&_mutex4);
    auto it = _mapAddr4.find(addr.s_addr);
    if (it != _mapAddr4.end()) {
      // already exists
      delete it->second;
    }
    _mapAddr4[addr.s_addr] = entry;
    MUUNLOCK(&_mutex4);
  }

  //------------------------------------------------------------------------
  // add  IPv6 address mapping
  //------------------------------------------------------------------------
  virtual void add(in6_addr addr, std::string name, std::string path, std::string addrStr)
  {
    DnsAddrEntryImpl *entry = new DnsAddrEntryImpl(addr, name, path, addrStr);
    entry->_tAddedSec = time(NULL);

    vector<uint8_t> bytes(16);
    memcpy(bytes.data(), &addr, 16);

    MULOCK(&_mutex6);
    auto it = _mapAddr6.find(bytes);
    if (it != _mapAddr6.end()) {
      // already exists
      delete it->second;
    }
    _mapAddr6[bytes] = entry;
    MUUNLOCK(&_mutex6);
  }

  //------------------------------------------------------------------------
  // Reverse DNS lookup IPv4
  //------------------------------------------------------------------------
  virtual const DnsAddrEntry* lookup(in_addr addr) {
    return lookup(addr.s_addr);
  }

  //------------------------------------------------------------------------
  // Reverse DNS lookup IPv4
  //------------------------------------------------------------------------
  virtual const DnsAddrEntry* lookup(uint32_t addr) {
    DnsAddrEntry* entry = 0L;

    MULOCK(&_mutex4);

    auto it = _mapAddr4.find(addr);
    if (it != _mapAddr4.end())
      entry = it->second;

    MUUNLOCK(&_mutex4);

    return entry;
  }

  //------------------------------------------------------------------------
  // Reverse DNS lookup IPv6
  //------------------------------------------------------------------------
  virtual const DnsAddrEntry* lookup(in6_addr addr) {
    vector<uint8_t> bytes(16);
    memcpy(bytes.data(), &addr, 16);

    MULOCK(&_mutex6);

    DnsAddrEntry* entry=0L;
    auto it = _mapAddr6.find(bytes);
    if (it != _mapAddr6.end())
      entry = it->second;

    MUUNLOCK(&_mutex6);

    return entry;
  }

  //------------------------------------------------------------------------
  // Reverse DNS lookup IPv6
  //------------------------------------------------------------------------
  virtual const DnsAddrEntry* lookup(std::vector<uint8_t> addr) {

    MULOCK(&_mutex6);

    DnsAddrEntry* entry = 0L;

    auto it = _mapAddr6.find(addr);
    if (it != _mapAddr6.end())
      entry = it->second;

    MUUNLOCK(&_mutex6);

    return entry;
  }

  //------------------------------------------------------------------------
  // clear - empties all mappings
  //------------------------------------------------------------------------
  virtual void clear() {
    MULOCK(&_mutex4);
    while (!_mapAddr4.empty()) {
      auto it = _mapAddr4.begin();
      delete it->second;
      _mapAddr4.erase(it);
    }
    MUUNLOCK(&_mutex4);

    MULOCK(&_mutex6);
    while (!_mapAddr6.empty()) {
      auto it = _mapAddr6.begin();
      delete it->second;
      _mapAddr6.erase(it);
    }
    MUUNLOCK(&_mutex6);
  }

  //------------------------------------------------------------------------
  // CheckCleanup
  // will call removeOld if it's been CLEANUP_INTERVAL_SEC since last time.
  //------------------------------------------------------------------------
  virtual void CheckCleanup(time_t now) {

    if (_tLastCleanup == 0L) { _tLastCleanup = now; return ; }

    if ((now - _tLastCleanup) > CLEANUP_INTERVAL_SEC) {
      removeOld(now);
      _tLastCleanup = now;
    }
  }

  //------------------------------------------------------------------------
  //------------------------------------------------------------------------
  virtual int getNumEntriesV4() {
    int retval;
    MULOCK(&_mutex4);
    retval =  (int)_mapAddr4.size();
    MUUNLOCK(&_mutex4);
    return retval;
  }

  //------------------------------------------------------------------------
  //------------------------------------------------------------------------
  virtual int getNumEntriesV6() {
    int retval;
    MULOCK(&_mutex6);
    retval = (int)_mapAddr6.size();
    MUUNLOCK(&_mutex6);
    return retval;
  }


protected:

  //------------------------------------------------------------------------
  //------------------------------------------------------------------------
  virtual void removeOld(time_t now)
  {
    MULOCK(&_mutex4);
    auto it = _mapAddr4.begin();
    while (it != _mapAddr4.end()) {
      time_t tdiff = now - it->second->_tAddedSec;
      if (tdiff > OLD_ENTRY_SECONDS) {
        delete it->second;
        _mapAddr4.erase(it++);
      } else
        it++;
    }
    MUUNLOCK(&_mutex4);

    {
      MULOCK(&_mutex6);
      auto it = _mapAddr6.begin();
      while (it != _mapAddr6.end()) {
        time_t tdiff = now - it->second->_tAddedSec;
        if (tdiff > OLD_ENTRY_SECONDS) {
          delete it->second;
          _mapAddr6.erase(it++);
        } else
          it++;
      }
      MUUNLOCK(&_mutex6);
    }
  }


  std::map<in_addr_t,DnsAddrEntryImpl*> _mapAddr4;
  std::map<vector<uint8_t>,DnsAddrEntryImpl*> _mapAddr6;
  MUTEX_T _mutex4;
  MUTEX_T _mutex6;
  time_t _tLastCleanup;
};


DnsRMap* DnsRMapNew() { return new DnsRMapImpl(); }
