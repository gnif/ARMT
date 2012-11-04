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

#include <sys/stat.h>
#include <assert.h>
#include <stdint.h>
#include <sstream>
#include <fstream>
#include <string.h>

#include "polarssl/sha1.h"
#include "polarssl/base64.h"
#include "polarssl/x509write.h"

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
  m_http.SetHeader("Content-Type"   , "application/octet-stream");
  m_http.SetHeader("Accept-Encoding", "");
  m_http.SetHeader("Connection"     , "close");

  InitAuth();
}

CMessageBuilder::~CMessageBuilder()
{
  rsa_free (&m_rsa);
}

bool CMessageBuilder::SignPayload(const std::string &payload, std::string &signature)
{
  /* hash the payload */
  unsigned char tmp[20];
  sha1((const unsigned char *)payload.c_str(), payload.length(), tmp);

  /* sign the hash */
  unsigned char buffer[m_rsa.len];
  if (rsa_pkcs1_sign(
    &m_rsa,
    ctr_drbg_random,
    CCommon::GetDRBG(),
    RSA_PRIVATE,
    SIG_RSA_SHA1,
    sizeof(tmp),
    tmp,
    buffer
  ) != 0)
    return false;

  /* base64 encode the signature */
  signature = Base64Encode(std::string((char *)buffer, sizeof(buffer)));
  return true;
}

std::string CMessageBuilder::Base64Encode(const std::string &str)
{
  size_t baselen = 0;
  /* get the baselen */
  base64_encode(NULL, &baselen, (const unsigned char *)str.c_str(), str.length());

  /* encode the string */
  unsigned char base[baselen];
  if (base64_encode(base, &baselen, (const unsigned char *)str.c_str(), str.length()) != 0)
    return "";

  std::string result;
  result.assign((char *)base, baselen);
  return result;
}

void CMessageBuilder::InitAuth()
{
  const std::string certPath   = CCommon::GetBasePath() + "/ssl";
  const std::string rsaFile    = certPath + "/private.pem";

  if (!CCommon::IsDir(certPath))
    assert(mkdir(certPath.c_str(), S_IRWXU) == 0);

  /* init m_rsa */
  rsa_init(&m_rsa, RSA_PKCS_V15, 0);

  /* check if we have an RSA key, and if not generate one */
  if (!CCommon::IsFile(rsaFile))
  {
    assert(rsa_gen_key(&m_rsa, ctr_drbg_random, CCommon::GetDRBG(), 2048, 65537) == 0);

    /* save the key off */
    FILE *fp;
    assert(fp = fopen(rsaFile.c_str(), "w"));

    assert(
      mpi_write_file("", &m_rsa.N , 16, fp) == 0 &&
      mpi_write_file("", &m_rsa.E , 16, fp) == 0 &&
      mpi_write_file("", &m_rsa.D , 16, fp) == 0 &&
      mpi_write_file("", &m_rsa.P , 16, fp) == 0 &&
      mpi_write_file("", &m_rsa.Q , 16, fp) == 0 &&
      mpi_write_file("", &m_rsa.DP, 16, fp) == 0 &&
      mpi_write_file("", &m_rsa.DQ, 16, fp) == 0 &&
      mpi_write_file("", &m_rsa.QP, 16, fp) == 0
    );

    fclose(fp);
    if (chmod(rsaFile.c_str(), S_IRUSR | S_IWUSR) != 0)
    {
      printf("Unable to secure private key\n");
      unlink(rsaFile.c_str());
      assert(false);
    }
  }
  else
  {
    /* load the private key */
    FILE *fp;
    assert(fp = fopen(rsaFile.c_str(), "r"));

    assert(
      mpi_read_file(&m_rsa.N , 16, fp) == 0 &&
      mpi_read_file(&m_rsa.E , 16, fp) == 0 &&
      mpi_read_file(&m_rsa.D , 16, fp) == 0 &&
      mpi_read_file(&m_rsa.P , 16, fp) == 0 &&
      mpi_read_file(&m_rsa.Q , 16, fp) == 0 &&
      mpi_read_file(&m_rsa.DP, 16, fp) == 0 &&
      mpi_read_file(&m_rsa.DQ, 16, fp) == 0 &&
      mpi_read_file(&m_rsa.QP, 16, fp) == 0
    );

    m_rsa.len = mpi_size(&m_rsa.N);

    fclose(fp);
  }
}

void CMessageBuilder::AppendSegment(const std::string &name, SegmentFn fn)
{
  m_segments[name] = fn;
}

void CMessageBuilder::Reset()
{
  m_segments.clear();
}

void CMessageBuilder::PackString(std::ostream &ss, const std::string &value)
{
  uint16_t len = value.length();

  /* we need to always send in LE */
  if (CCommon::IsBE())
    swab(&len, &len, sizeof(len));

  ss.write((const char *)&len, sizeof(len));
  ss << value;
}

bool CMessageBuilder::Send()
{
  std::string body;
  {
    bool send = false;
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
      send = true;
    }

    /* if there is nothing to send, do not do anything */
    if (!send)
      return true;

    std::stringstream compressed;
    CCompress::Deflate(total, compressed);
    body = compressed.str();
  }

  /* connect to the host */
  if (!m_http.Connect(m_armthost, m_armtport, true))
    return false;

  /* encode the public key for transmission */
  std::string pubkey;
  {
    unsigned char buffer[1024];

   int len = x509_write_pubkey_der(buffer, sizeof(buffer), &m_rsa);
   if (len <= 0)
      return false;

    pubkey = Base64Encode(std::string(
      (char *)buffer + sizeof(buffer) - len - 1, /* the key is in the end of the buffer */
      len
    ));
  }

  std::string signature;
  if (!SignPayload(body, signature))
    return false;

  m_http.SetHeader("X-ARMT-HOST"   , m_hostname);
  m_http.SetHeader("X-ARMT-IP"     , m_http.GetLocalIP());
  m_http.SetHeader("X-ARMT-PUB"    , pubkey);
  m_http.SetHeader("X-ARMT-SIG"    , signature);
  m_http.SetHeader("Content-Length", CCommon::IntToStr(body.length()));

  /* send the message */
  uint16_t error;
  CHTTP::HeaderMap headers;
  if (!m_http.PerformRequest("POST", "/", error, headers, body))
    return false;

  printf("%d\n", error);
  printf("%s\n", body.c_str());

  return error == 202;
}

