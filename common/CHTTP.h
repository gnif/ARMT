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

#ifndef _CHTTP_H_
#define _CHTTP_H_

#include <stdint.h>
#include <string>
#include <sstream>
#include <map>

#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

class CHTTP
{
  public:
    CHTTP();
    ~CHTTP();

    bool Connect(const std::string &host, const int port, const bool ssl);
    void Disconnect();
    const std::string &GetLocalIP() { return m_localIP; }

    void SetHeader(const std::string &name, const std::string &value);
    void DelHeader(const std::string &name);
    void ClearHeaders();

    typedef std::map<std::string, std::string> HeaderMap;

    /**
      * Performs a HTTP request
      * @param  method  The HTTP method to use (ie: GET, POST)
      * @param  error   The HTTP error response code (ie: 200, 404)
      * @param  headers The HTTP headers returned
      * @param  body    This is input and output, input will be the body of the request, output will be the body of the reply
      * @return         True if valid HTTP communication was established with the server, not if error == 200.
      */   
    bool PerformRequest(const char *method, const std::string &uri, uint16_t &error, HeaderMap &headers, std::string &body);

  private:
    bool             m_connected;
    bool             m_ssl;
    std::string      m_localIP;
    HeaderMap        m_headers;

    /* polarssl vars */
    entropy_context  m_entropy;
    ctr_drbg_context m_ctr_drbg;
    ssl_context      m_sslContext;
    ssl_session      m_sslSession;
    int              m_sslFD;

    bool Write(const std::string &buffer);
    bool Read (std::stringstream &buffer);

    void AppendHeaders(std::stringstream &request);
};

#endif // _CHTTP_H_
