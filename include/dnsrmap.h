#ifndef _DNSRMAP_H_
#define _DNSRMAP_H_

#include <stdint.h>

#ifdef WIN32
#include <Ws2tcpip.h>
#else // WIN32
#include <netinet/in.h>
#endif // WIN32

#include <string>
#include <vector>

class DnsAddrEntry
{
public:
  virtual std::string getName() const =0;
  virtual std::string getPath()=0;	// domain||cname1||cname2  - can be empty
  virtual bool        isV6()=0;
  virtual in_addr     getAddr4()=0;
  virtual in6_addr    getAddr6()=0;
  virtual std::string getAddrStr()=0;
};

// Reverse DMS map interface
class DnsRMap
{
public:
  //virtual ~DnsRMap(){}

  // add a mapping
  virtual void add(in_addr  addr, std::string name, std::string path, std::string addrStr)=0;
  virtual void add(in6_addr addr, std::string name, std::string path, std::string addrStr)=0;

  // lookup IPV4
  virtual const DnsAddrEntry* lookup(in_addr addr)=0;
  virtual const DnsAddrEntry* lookup(uint32_t addr)=0;

  // lookup IPv6
  virtual const DnsAddrEntry* lookup(in6_addr addr)=0;
  virtual const DnsAddrEntry* lookup(std::vector<uint8_t> addr)=0;

  // getter for size
  virtual int getNumEntriesV4()=0;
  virtual int getNumEntriesV6()=0;

  // remove all entries - only public for testing
  virtual void clear()=0;
  // only public for testing - called internally in add()
  virtual void CheckCleanup(time_t now)=0;
};

extern DnsRMap* DnsRMapNew();

#endif // _DNSRMAP_H_
