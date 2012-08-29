/*
 * ARMT (Another Remote Monitoring Tool)
 * Copyright (C) Geoffrey McRae 2012 <geoff@spacevs.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include "CDNS.h"

#include <algorithm>
#include <sstream>

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct
{
  uint16_t ID;
  uint16_t flags;
  uint16_t QDCOUNT;
  uint16_t ANCOUNT;
  uint16_t NSCOUNT;
  uint16_t ARCOUNT;
} __attribute__ ((packed)) DNSQuery;

typedef struct
{
  uint16_t QTYPE;
  uint16_t QCLASS;
} __attribute__ ((packed)) DNSQuestion;

typedef struct
{
  uint16_t TYPE;
  uint16_t CLASS;
  uint32_t TTL;
  uint16_t RDLENGTH;
} __attribute__ ((packed)) DNSAnswer;

#define DNS_FLAG_QR            (0x1 << 15)
#define DNS_FLAG_OPCODE_MASK   (0xF << 11)
#define DNS_FLAG_OPCODE_QUERY  (0x0 << 11)
#define DNS_FLAG_OPCODE_IQUERY (0x1 << 11)
#define DNS_FLAG_OPCODE_STATUS (0x2 << 11)
#define DNS_FLAG_AA            (0x1 << 10)
#define DNS_FLAG_TC            (0x1 <<  9)
#define DNS_FLAG_RD            (0x1 <<  8)
#define DNS_FLAG_RA            (0x1 <<  7)
#define DNS_FLAG_Z_MASK        (0x7 <<  4)
#define DNS_FLAG_RCODE_MASK    (0xF <<  0)
#define DNS_FLAG_RCODE_OK      (0x0)

#define DNS_TYPE_A   0x1
#define DNS_CLASS_IN 0x1

CDNS::CDNS()
{
}

CDNS::~CDNS()
{
}

void CDNS::AddResolver(const std::string &resolver)
{
  if (std::find(m_resolvers.begin(), m_resolvers.end(), resolver) != m_resolvers.end())
    return;

  m_resolvers.push_back(resolver);
}

CCommon::StringList CDNS::GetIPv4(const std::string &fqdn)
{
  CCommon::StringList result;
  std::time_t t = std::time(0);

  CacheMap::iterator pair = m_cache.find(fqdn);
  if (pair != m_cache.end())
  {
    CacheList &list = pair->second;
    for(CacheList::iterator entry = list.begin(); entry != list.end();)
    {
      /* look for expired entries and remove them */
      if (entry->expire <= t)
      {
        entry = list.erase(entry);
        continue;
      }

      result.push_back(entry->ipv4);
      ++entry;
    }
  }

  /* if we had cached records, return them */
  if (!result.empty())
    return result;

  /* perform a DNS lookup */
  if (DNSLookup(fqdn))
  {
    /* if success, return the list */
    CacheList &list = m_cache[fqdn];
    for(CacheList::iterator entry = list.begin(); entry != list.end(); ++entry)
      result.push_back(entry->ipv4);
  }

  return result;
}

struct hostent *CDNS::GetHostByName(const std::string &fqdn)
{
  CCommon::StringList addresses = GetIPv4(fqdn);
  if (addresses.empty())
    return NULL;

  struct hostent *result = new struct hostent;

  result->h_name = new char[fqdn.length() + 1];
  memcpy(result->h_name, fqdn.c_str(), fqdn.length() + 1);

  result->h_aliases    = new char*[1];
  result->h_aliases[0] = NULL;
  result->h_addrtype   = AF_INET;
  result->h_length     = sizeof(uint32_t);

  int i = 0;
  result->h_addr_list  = new char*[addresses.size() + 1];
  for(CCommon::StringListIterator addr = addresses.begin(); addr != addresses.end(); ++addr)
  {
    uint32_t *in = new uint32_t;
    inet_pton(AF_INET, addr->c_str(), in);
    result->h_addr_list[i++] = (char*)in;
  }
  result->h_addr_list[i] = NULL;

  return result;
}

void CDNS::Free(struct hostent *addr)
{
  delete[] addr->h_name;
  delete[] addr->h_aliases;
  for(int i = 0; addr->h_addr_list[i] != NULL; ++i)
    delete addr->h_addr_list[i];
  delete[] addr->h_addr_list;
  delete addr;
}

std::string CDNS::ParseDNSName(unsigned char *buffer, unsigned char *offset, unsigned int &len)
{
  bool followed = false;
  std::stringstream domain;

  /* offset at 1, as we need to count the null terminator and the first length byte */
  len = 1;

  while(*offset > 0)
  {
    /* follow DNS compression pointers */
    if (!followed && (*offset & 0xC0) == 0xC0)
    {
      followed = true;
      offset   = buffer + sizeof(DNSQuery) + (*offset & ~0xC0);
      ++len;
      continue;
    }

    domain.write((char*)&offset[1], *offset);
    if (!followed)
      len += (*offset + 1);

    offset += (*offset + 1);

    if (*offset > 0)
      domain << ".";
  }
  return domain.str();
}

bool CDNS::DNSLookup(const std::string& host)
{
  bool success = false;

  /* build the DNS question */
  uint8_t buffer[sizeof(DNSQuery) + host.length() + 2 + sizeof(DNSQuestion)];
  memset(buffer, 0, sizeof(buffer));

  DNSQuery *query = (DNSQuery*)buffer;
  query->ID      = rand() % UINT16_MAX;
  query->flags   = DNS_FLAG_OPCODE_QUERY | DNS_FLAG_RD;
  query->QDCOUNT = 1;

  /* add the hostname */
  memcpy(buffer + sizeof(DNSQuery) + 1, host.c_str(), host.length() + 1);
  uint8_t *ptr = buffer + sizeof(DNSQuery) + 1;
  uint8_t len = 0;
  while(*ptr != '\0')
  {
    if (ptr[len] == '.' || ptr[len] == '\0')
    {
      ptr[-1] = len;
      ptr    += len + 1;
      len     = 0;
      continue;
    }
    ++len;
  }
  
  /* set the question type */
  DNSQuestion *question = (DNSQuestion*)(buffer + sizeof(DNSQuery) + host.length() + 2);
  question->QTYPE  = DNS_TYPE_A;
  question->QCLASS = DNS_CLASS_IN;
  if (!CCommon::IsBE())
  {
    swab(query   , query   , sizeof(DNSQuery   ));
    swab(question, question, sizeof(DNSQuestion));
  }

  for(CCommon::StringListIterator server = m_resolvers.begin(); server != m_resolvers.end(); ++server)
  {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    struct timeval timeout;
    timeout.tv_sec  = 5;
    timeout.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

    struct sockaddr_in addr;
    inet_pton(AF_INET, server->c_str(), &addr.sin_addr.s_addr);
    addr.sin_family = AF_INET;
    addr.sin_port    = htons(53);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
      close(fd);
      continue;
    }

    /* send the request */
    if (send(fd, buffer, sizeof(buffer), 0) < (ssize_t)sizeof(buffer))
    {
      close(fd);
      continue;
    }

    /* wait for the reply and get the size */
    ssize_t size = recv(fd, NULL, 0, MSG_PEEK | MSG_WAITALL | MSG_TRUNC);
    if (size < (ssize_t)sizeof(DNSQuery))
    {
      close(fd);
      continue;
    }

    /* allocate a buffer and read the reply */
    unsigned char buffer[size];
    recv(fd, buffer, size, MSG_WAITALL);

    query = (DNSQuery*)buffer;
    if (!CCommon::IsBE())
      swab(query, query, sizeof(DNSQuery));

    /* check that the reply is valid and there was no error */
    if (!(query->flags & DNS_FLAG_QR) || (query->flags & DNS_FLAG_RCODE_MASK) != DNS_FLAG_RCODE_OK)
      continue;

    success = true;

    unsigned int len;
    std::string domain;

    unsigned char *offset = buffer + sizeof(DNSQuery);
    for(unsigned int i = 0; i < query->QDCOUNT; ++i)
    {
      /* we dont care about questions, we just skip over them */
      domain = ParseDNSName(buffer, offset, len);
      offset += len + sizeof(DNSQuestion);
    }

    for(unsigned int i = 0; i < query->ANCOUNT; ++i)
    {
      domain = ParseDNSName(buffer, offset, len);
      offset += len;

      DNSAnswer *answer = (DNSAnswer*)offset;
      if (!CCommon::IsBE())
      {
        swab(&answer->TYPE    , &answer->TYPE    , sizeof(uint16_t));
        swab(&answer->CLASS   , &answer->CLASS   , sizeof(uint16_t));
        swab(&answer->RDLENGTH, &answer->RDLENGTH, sizeof(uint16_t));
        answer->TTL =
            ((answer->TTL & 0xFF000000) >> 24) |
            ((answer->TTL & 0x00FF0000) >>  8) |
            ((answer->TTL & 0x0000FF00) <<  8) |
            ((answer->TTL & 0x000000FF) << 24);
      }

      offset += sizeof(DNSAnswer);

      /* we want IPv4 internet addresses only */
      if (answer->TYPE != DNS_TYPE_A || answer->CLASS != DNS_CLASS_IN || answer->RDLENGTH != 4)
      {
        offset += answer->RDLENGTH;
        continue;
      }

      std::stringstream ipv4;
      ipv4 <<
        CCommon::IntToStr(offset[0]) << "." <<
        CCommon::IntToStr(offset[1]) << "." <<
        CCommon::IntToStr(offset[2]) << "." <<
        CCommon::IntToStr(offset[3]);

      offset += answer->RDLENGTH;

      CacheRecord record;
      record.expire = std::time(0) + answer->TTL;
      record.ipv4   = ipv4.str();
      m_cache[host].push_back(record);
    }

    close(fd);
    return success;
  }

  return false;
}

