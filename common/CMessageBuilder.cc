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

#include "CMessageBuilder.h"
#include "CCommon.h"
#include "CCompress.h"

#include <assert.h>
#include <stdint.h>
#include <sstream>
#include <string.h>
#include "polarssl/md5.h"

CMessageBuilder::CMessageBuilder(const std::string &host, const unsigned int port) :
  m_armthost(host),
  m_armtport(port)
{
  /* get the system's hostname */
  char buffer[256];
  buffer[sizeof(buffer)-1] = '\0';
  gethostname(buffer, sizeof(buffer)-1);
  m_hostname.assign(buffer);

  getdomainname(buffer, sizeof(buffer)-1);
  ssize_t len = strlen(buffer);
  if (len > 0 && strcmp(buffer, "(none)") != 0)
  {
    m_hostname.append(".");
    m_hostname.append(buffer, len);
  }

  m_http.SetHeader("Host"           , host);
  m_http.SetHeader("User-Agent"     , "ARMT");
  m_http.SetHeader("Accept"         , "text/plain");
  m_http.SetHeader("Accept-Encoding", "");
  m_http.SetHeader("Connection"     , "close");
  m_http.SetHeader("X-ARMT-HOST"    , m_hostname);
}

void CMessageBuilder::AppendSegment(const std::string &name, SegmentFn fn)
{
  m_segments[name] = fn;
}

void CMessageBuilder::PackString(std::ostream &ss, const std::string &value)
{
  uint16_t len = value.length();
  ss.write((const char *)&len, sizeof(len));
  ss << value;
}

bool CMessageBuilder::Send()
{
  std::string body;
  {
    std::stringstream total;
    for(SegmentList::iterator segment = m_segments.begin(); segment != m_segments.end(); ++segment)
    {
      uint8_t namelen = segment->first.length();
      assert(namelen <= 0xFF);

      /* get the data */
      std::stringstream ss;
      if (!segment->second(ss))
        continue;

      uint32_t datalen = ss.tellp();
      ss.seekg(0, std::stringstream::beg);

      total.write((const char *)&namelen, sizeof(namelen));
      total.write((const char *)&datalen, sizeof(datalen));
      total << segment->first << ss.str();
    }


    std::stringstream compressed;
    CCompress::Deflate(total, compressed);
    body = compressed.str();
  }

  {
    /* hash the body for the header */
    unsigned char tmp[16];
    md5((const unsigned char *)body.c_str(), body.length(), tmp);
    std::string hash;
    for(int i = 0; i < 16; ++i)
    {
      std::string dec = CCommon::IntToStr(tmp[i], 16);
      if(dec.length() < 2)
        dec.insert(0, "0");
      hash.append(dec);
    }
    m_http.SetHeader("X-ARMT-MD5", hash);
  }

  m_http.SetHeader("Content-Length", CCommon::IntToStr(body.length()));

  /* send the message */
  uint16_t error;
  CHTTP::HeaderMap headers;
  if (
    !m_http.Connect(m_armthost, m_armtport, true) ||
    !m_http.PerformRequest("POST", "/armt/db_upload.php", error, headers, body)
  )
    return false;

  printf("%d\n", error);
  printf("%s\n", body.c_str());

  return true;
}

