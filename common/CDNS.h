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

#ifndef _CDNS_H_
#define _CDNS_H_

#include <stdint.h>
#include <string>
#include <map>
#include <vector>
#include <ctime>
#include <netdb.h>

#include "CCommon.h"

class CDNS
{
  public:
    CDNS();
    ~CDNS();

    void                AddResolver  (const std::string &resolver);
    CCommon::StringList GetIPv4      (const std::string &fqdn    );
    struct hostent     *GetHostByName(const std::string &fqdn    ); /* returns a gethostbyname compatible struct */
    void                Free         (struct hostent *addr       );

  private:
    typedef struct
    {
      std::time_t expire;
      std::string ipv4;
    } CacheRecord;

    typedef std::vector<CacheRecord           > CacheList;
    typedef std::map   <std::string, CacheList> CacheMap;
    typedef std::pair  <std::string, CacheList> CachePair;

    CCommon::StringList m_resolvers;
    CacheMap            m_cache;

    std::string ParseDNSName(unsigned char *buffer, unsigned char *offset, unsigned int &len);
    bool        DNSLookup   (const std::string& host);
};

#endif // _CDNS_H_
