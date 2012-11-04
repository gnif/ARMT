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

#ifndef _CMESSAGEBUILDER_H_
#define _CMESSAGEBUILDER_H_

#include "CHTTP.h"

#include <string>
#include <map>

#include "polarssl/x509.h"
#include "polarssl/rsa.h"

class CMessageBuilder
{
  public:
    typedef bool (*SegmentFn)(std::iostream &ss);

    CMessageBuilder(const std::string &host, const unsigned int port);
    ~CMessageBuilder();

    bool SignPayload(const std::string &payload, std::string &signature);
    std::string Base64Encode(const std::string &str);

    bool LoadCertificate(const std::string &crt);
    void InitAuth();

    void AppendSegment(const std::string &name, SegmentFn fn);
    void Reset();
    bool Send(int &result);

    static void PackString(std::ostream &ss, const std::string &value);
  private:
    typedef std::map<std::string, SegmentFn> SegmentList;

    std::string  m_armthost;
    unsigned int m_armtport;

    /* our key for signing messages */
    rsa_context  m_rsa;

    std::string  m_hostname;
    SegmentList  m_segments;
    CHTTP        m_http;
};

#endif // _CMESSAGEBUILDER_H_
