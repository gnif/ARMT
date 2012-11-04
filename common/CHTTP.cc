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

#include "CCommon.h"
#include "RootCerts.h"
#include "polarssl/net.h"
#include <sys/socket.h>
#include <pcrecpp.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>

CHTTP::CHTTP() :
  m_connected(false)
{
  x509_cert *current;
  m_sslCACerts = current = new x509_cert;
  memset(current, 0, sizeof(x509_cert));

  for(int i = 0; ; ++i)
  {
    x509parse_crt(current, (unsigned char *)RootCerts[i], strlen(RootCerts[i]));
    if (RootCerts[i+1] == NULL)
      break;

    current->next = new x509_cert;
    memset(current->next, 0, sizeof(x509_cert));
    current = current->next;
  }
}

CHTTP::~CHTTP()
{
  Disconnect();

  while(m_sslCACerts->next)
  {
    /* save the pointer to the next record */
    x509_cert *next = m_sslCACerts->next;

    /* free the cert and the x509_cert struct */
    x509_free(m_sslCACerts);
    delete m_sslCACerts;

    /* move onto the next record */
    m_sslCACerts = next;
  }
}

bool CHTTP::Connect(const std::string &host, const int port, const bool ssl)
{
  if (m_connected)
    return false;

  m_ssl = ssl;

  if (ssl)
  {
    memset(&m_sslContext, 0, sizeof(m_sslContext));
    memset(&m_sslSession, 0, sizeof(m_sslSession));

    if (net_connect(&m_sslFD, host.c_str(), port) != 0)
      return false;

    ssl_init            (&m_sslContext);
    ssl_set_endpoint    (&m_sslContext, SSL_IS_CLIENT);
    ssl_set_authmode    (&m_sslContext, SSL_VERIFY_OPTIONAL);
    ssl_set_rng         (&m_sslContext, ctr_drbg_random, CCommon::GetDRBG());
    ssl_set_bio         (&m_sslContext, net_recv, &m_sslFD, net_send, &m_sslFD);
    ssl_set_ciphersuites(&m_sslContext, ssl_default_ciphersuites);
    ssl_set_session     (&m_sslContext, 1, 600, &m_sslSession);
    ssl_set_ca_chain    (&m_sslContext, m_sslCACerts, NULL, host.c_str());

    struct sockaddr_in local_address;
    socklen_t addr_size = sizeof(local_address);
    getsockname(m_sslFD, (sockaddr *)&local_address, &addr_size);

    /* handshake */
    int ret;
    while((ret = ssl_handshake(&m_sslContext)) != 0)
    {
      if (ret != POLARSSL_ERR_NET_WANT_READ  || ret != POLARSSL_ERR_NET_WANT_WRITE)
      {
        fprintf(stderr, "CHTTP::Connect - Failed to perform SSL handshake\n");
        return false;
      }
    }

    /* check the certificate */
    if ((ret = ssl_get_verify_result(&m_sslContext)) != 0)
    {
      fprintf(stderr, "CHTTP::Connect - SSL certificate failed to verify:\n");
      if (ret & BADCERT_EXPIRED    ) fprintf(stderr, " * BADCERT_EXPIRED\n"    );
      if (ret & BADCERT_REVOKED    ) fprintf(stderr, " * BADCERT_REVOKED\n"    );
      if (ret & BADCERT_CN_MISMATCH) fprintf(stderr, " * BADCERT_CN_MISMATCH\n");
      if (ret & BADCERT_NOT_TRUSTED) fprintf(stderr, " * BADCERT_NOT_TRUSTED\n");
      fprintf(stderr, "\n");

      return false; 
    }

    char s[16];
    inet_ntop(AF_INET, &local_address.sin_addr, s, sizeof(s));
    m_localIP.assign(s);

    m_connected = true;
    return true;
  }
  else
  {
    /* FIXME */
    return false;
  }

}

void CHTTP::Disconnect()
{
  if (!m_connected)
    return;

  if (m_ssl)
  {
    ssl_close_notify(&m_sslContext);
    net_close       (m_sslFD);
    ssl_free        (&m_sslContext);
    memset          (&m_sslContext, 0, sizeof(m_sslContext));
  }
  else
  {
    /* FIXME */
  }

  m_connected = false;
}

void CHTTP::SetHeader(const std::string &name, const std::string &value)
{
  std::string key = CCommon::StrToLower(name);
  m_headers[key] = value; 
}

void CHTTP::DelHeader(const std::string &name)
{
  std::string key = CCommon::StrToLower(name);
  HeaderMap::iterator header = m_headers.find(key);
  if (header != m_headers.end())
    m_headers.erase(header);
}

void CHTTP::ClearHeaders()
{
  m_headers.clear();
}

void CHTTP::AppendHeaders(std::stringstream &request)
{
  for(HeaderMap::iterator header = m_headers.begin(); header != m_headers.end(); ++header)
  {
    for(unsigned int i = 0; i < header->first.length(); ++i)
    {
      if (i == 0 || header->first[i-1] == '-')
           request << (char)std::toupper(header->first[i]);
      else request << (char)header->first[i];
    }

    request << ": " << header->second << "\r\n";
  }
}

bool CHTTP::Write(const std::string &buffer)
{
  if (!m_connected)
    return false;

  int ret;
  if (m_ssl)
  {
    int offset = 0;
    int length = buffer.length();

    while(length > 0)
    {
      ret = ssl_write(&m_sslContext, (unsigned char*)buffer.c_str() + offset, length);
      if (ret <= 0)
      {
        if (ret == POLARSSL_ERR_NET_WANT_WRITE)
          continue;
        return false;
      }

      offset += ret;
      length -= ret;
    }
    return length == 0;
  }
  else
  {
    /* FIXME */
    return false;
  }
}

bool CHTTP::Read(std::stringstream &buffer)
{
  if (!m_connected)
    return false;

  int ret;
  if (m_ssl)
  {
    buffer.str(std::string());
    while(1)
    {
      unsigned char result[1024];
      ret = ssl_read(&m_sslContext, result, sizeof(result));
      if (ret == POLARSSL_ERR_NET_WANT_READ)
        continue;

      if (ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0)
      {
        Disconnect();
        return true;
      }

      if(ret < 0)
        return false;

      buffer.write((char*)result, ret);
    }
    return true;
  }
  else
  {
    /* FIXME */
    return false;
  }
}

bool CHTTP::PerformRequest(const char *method, const std::string &uri, int &error, HeaderMap &headers, std::string &body)
{
  error = 0;
  headers.clear();

  std::stringstream request, result;
  request << method << " " << uri << " HTTP/1.0\r\n";
  AppendHeaders(request);
  request << "\r\n";
  request << body;

  if (!Write(request.str()))
    return false;

  if (!Read(result))
    return false;

  /* break apart the response */
  pcrecpp::RE_Options  options;
  options.set_multiline(true);
  options.set_dotall   (true);
  std::string httpVersion, httpError, httpMsg, httpHeaders, httpBody;
  if (!pcrecpp::RE(
      "^HTTP/(\\d\\.\\d)\\s+(\\d+)\\s+(.+?)(?:\\r\\n|\\n|\\r)(.+?)(?:\\r\\n\\r\\n|\\n\\n|\\r\\r)(.*)$",
      options
    ).FullMatch(result.str(),
      &httpVersion,
      &httpError,
      &httpMsg,
      &httpHeaders,
      &body
    )) return false;

  /* parse the HTTP error code */
  error = strtoul(httpError.c_str(), NULL, 10);

  /* break apart the headers */
  pcrecpp::StringPiece input(httpHeaders);
  pcrecpp::RE re("^([^ :]+): (.+)(?:\\r\\n|\\n|\\r)");
  std::string name, value;
  while(re.FindAndConsume(&input, &name, &value))
  {
    name = CCommon::StrToLower(name);

    /* look for duplicate headers and append an index onto them  */
    /* this is an ugly hack, but it is fine for our requirements */
    if (headers.find(name) != headers.end())
    {
      int i = 1;
      while(headers.find(name + CCommon::IntToStr(i)) != headers.end())
        ++i;
      name += CCommon::IntToStr(i);
    }

    headers[CCommon::StrToLower(name)] = value;
  }

  return true;
}
