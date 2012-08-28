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

#include "CHTTP.h"

#include "polarssl/net.h"

CHTTP::CHTTP()
{
}

CHTTP::~CHTTP()
{
  DeInitialize();
}

bool CHTTP::Initialize(const std::string &host, const int port, const bool ssl)
{
  m_ssl = ssl;

  if (ssl)
  {
    const char *pers = "ARMT_CHTTPS";
    entropy_init(&m_entropy);
    if (ctr_drbg_init(&m_ctr_drbg, entropy_func, &m_entropy, (unsigned char* )pers, strlen(pers)) != 0)
      return false;

    memset(&m_sslContext, 0, sizeof(m_sslContext));
    memset(&m_sslSession, 0, sizeof(m_sslSession));

    if (net_connect(&m_sslFD, host.c_str(), port) != 0)
      return false;

    ssl_init            (&m_sslContext);
    ssl_set_endpoint    (&m_sslContext, SSL_IS_CLIENT);
    ssl_set_authmode    (&m_sslContext, SSL_VERIFY_NONE);
    ssl_set_rng         (&m_sslContext, ctr_drbg_random, &m_ctr_drbg);
    ssl_set_bio         (&m_sslContext, net_recv, &m_sslFD, net_send, &m_sslFD);
    ssl_set_ciphersuites(&m_sslContext, ssl_default_ciphersuites);
    ssl_set_session     (&m_sslContext, 1, 600, &m_sslSession);

    char buffer[1024];
    int len = sprintf(buffer,
      "GET / HTTP/1.0\r\n"
      "\r\n"
    );
    ssl_write(&m_sslContext, (unsigned char*)buffer, len);

    std::string out;
    while(1)
    {
      unsigned char result[1024];
      int ret = ssl_read(&m_sslContext, result, sizeof(result));
      if (ret == POLARSSL_ERR_NET_WANT_READ || ret == POLARSSL_ERR_NET_WANT_WRITE)
        continue;

      if(ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY || ret <= 0)
        break;

      out.append((char*)result, ret);
    }

    ssl_close_notify(&m_sslContext);
    printf("%s\n", out.c_str());
  }

  return true;
}

void CHTTP::DeInitialize()
{
  if (m_ssl)
  {
    net_close(m_sslFD);
    ssl_free (&m_sslContext);
    memset   (&m_sslContext, 0, sizeof(m_sslContext));
  }

}
