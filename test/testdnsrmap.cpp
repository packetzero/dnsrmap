#include <gtest/gtest.h>
#include <string>
#include <vector>
using namespace std;

#include "../include/dnsrmap.h"

#ifdef WIN32
#include <Ws2tcpip.h>
#else // WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif // WIN32


int parse_addr6(std::string addr6, in6_addr &val) {
  return inet_pton(AF_INET6, addr6.c_str(), (void *) &val);
}

int parse_addr4(std::string addr4, in_addr &val) {
  return inet_pton(AF_INET, addr4.c_str(), (void *) &val);
}

static string _MockV4Name="p.typekit.net";
static string _MockV4AddrStr="23.76.195.26";
static in_addr _MockV4Addr;

static string _MockV4NameB="tomsitpro.com";
static string _MockV4AddrStrB="35.165.241.239";
static in_addr _MockV4AddrB;

static string _MockV4NameC="lb.geo.office365.com";
static string _MockV4AddrStrC="40.97.30.130";
static in_addr _MockV4AddrC;

// DNS that maps to multiple IPV6 addresses
static string _MockV6NameA="lb.geo.office365.com";
static string _MockV6PathA = "lb.geo.office365.com||outlook-namsouth.office365.com";
static string _MockV6AddrStrA1="2600:1404:27:2a2::20c1";
static string _MockV6AddrStrA2="2600:1404:27:299::20c1";
static in6_addr _MockV6AddrA1;
static in6_addr _MockV6AddrA2;


class DnsRMapTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    parse_addr4(_MockV4AddrStr, _MockV4Addr);
    parse_addr4(_MockV4AddrStrB, _MockV4AddrB);
    parse_addr4(_MockV4AddrStrC, _MockV4AddrC);

    parse_addr6(_MockV6AddrStrA1, _MockV6AddrA1);
    parse_addr6(_MockV6AddrStrA2, _MockV6AddrA2);
  }

  // virtual void TearDown() {}
};


TEST_F(DnsRMapTest, single)
{
  DnsRMap *rmap = DnsRMapNew();

  rmap->add(_MockV4Addr, _MockV4Name, "", _MockV4AddrStr);

  const DnsAddrEntry* entry = rmap->lookup(_MockV4Addr);
  ASSERT_TRUE(entry != 0L);
  ASSERT_EQ(_MockV4Name, entry->getName());
}

TEST_F(DnsRMapTest, removeOldEntries)
{
  DnsRMap *rmap = DnsRMapNew();

  rmap->add(_MockV4Addr, _MockV4Name, "", _MockV4AddrStr);

  ASSERT_EQ(rmap->getNumEntriesV4(), 1);

  rmap->CheckCleanup(time(NULL) + 60*60); // 1 hours ahead

  ASSERT_EQ(rmap->getNumEntriesV4(), 0);
}

// This packet lead to a parse error that had to be fixed.
TEST_F(DnsRMapTest, singleB)
{
  DnsRMap *rmap = DnsRMapNew();

  rmap->add(_MockV4AddrB, _MockV4NameB, "", _MockV4AddrStrB);

  const DnsAddrEntry* entry = rmap->lookup(_MockV4AddrB);
  ASSERT_TRUE(entry != 0L);
  ASSERT_EQ(_MockV4NameB, entry->getName());
}

TEST_F(DnsRMapTest, singlev6)
{
  DnsRMap *rmap = DnsRMapNew();

  rmap->add(_MockV6AddrA1, _MockV6NameA, "", _MockV6AddrStrA1);

  const DnsAddrEntry* entry = rmap->lookup(_MockV6AddrA1);

  ASSERT_TRUE(entry != 0L);
  ASSERT_EQ(_MockV6NameA, entry->getName());

  entry = rmap->lookup(_MockV6AddrA2);

  ASSERT_TRUE(entry == 0L);

  in6_addr addr6;
  parse_addr6("0000:1404:00:2a2::00", addr6);
  entry = rmap->lookup(addr6);

  ASSERT_TRUE(entry == 0L);
}

// make sure cleanup happens (with no side-effects) when adding entry to existing mapping
TEST_F(DnsRMapTest, duplicate)
{
  DnsRMap *rmap = DnsRMapNew();

  rmap->add(_MockV4Addr, _MockV4Name, "", _MockV4AddrStr);
  rmap->add(_MockV4Addr, _MockV4Name, "", _MockV4AddrStr);
  rmap->add(_MockV4Addr, _MockV4Name, "", _MockV4AddrStr);
  rmap->add(_MockV4Addr, _MockV4Name, "", _MockV4AddrStr);

  ASSERT_TRUE(rmap->lookup(_MockV4Addr) != 0L);

  rmap->add(_MockV6AddrA1, _MockV6NameA, _MockV6PathA, _MockV6AddrStrA1);
  rmap->add(_MockV6AddrA1, _MockV6NameA, _MockV6PathA, _MockV6AddrStrA1);
  rmap->add(_MockV6AddrA1, _MockV6NameA, _MockV6PathA, _MockV6AddrStrA1);
  rmap->add(_MockV6AddrA1, _MockV6NameA, _MockV6PathA, _MockV6AddrStrA1);

  ASSERT_TRUE(rmap->lookup(_MockV6AddrA1) != 0L);
}

TEST_F(DnsRMapTest, testCleanup)
{
  DnsRMap *rmap = DnsRMapNew();

  rmap->add(_MockV4Addr, _MockV4Name, "", _MockV4AddrStr);

  const DnsAddrEntry* entry = rmap->lookup(_MockV4Addr);
  ASSERT_TRUE(entry != 0L);
  ASSERT_EQ(_MockV4Name, entry->getName());

  rmap->clear();

  // should not
  entry = rmap->lookup(_MockV4Addr);
  ASSERT_TRUE(entry == 0L);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  int status= RUN_ALL_TESTS();
  return status;
}
