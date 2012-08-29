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

#include "CCompress.h"

#include <stdio.h>
#include "zlib.h"

bool CCompress::Deflate(std::istream &input, std::ostream &output)
{
  if (!input.good() || !output.good())
    return false;

  z_stream strm;
  strm.zalloc = Z_NULL;
  strm.zfree  = Z_NULL;
  strm.opaque = Z_NULL;

  int ret, flush;
  ret = deflateInit(&strm, Z_BEST_COMPRESSION);
  if (ret != Z_OK)
    return false;

  /* seek to the start of the stream */
  input.seekg(0);

  do
  {
    char bin [65535];
    char bout[65535];

    /* fill the buffer */
    input.read(bin, sizeof(bin));
    strm.avail_in = input.gcount();
    strm.next_in  = (unsigned char *)bin;
    flush = input.eof() ? Z_FINISH : Z_NO_FLUSH;

    /* deflate the data and append it */
    do
    {
      strm.avail_out = sizeof(bout);
      strm.next_out  = (unsigned char *)bout;

      ret = deflate(&strm, flush);
      output.write(bout, sizeof(bout) - strm.avail_out);
    }
    while (strm.avail_out == 0);

  }
  while (flush != Z_FINISH);

  deflateEnd(&strm);
  return true;
}

bool CCompress::Inflate(std::istream &input, std::ostream &output)
{
  if (!input.good() || !output.good())
    return false;

  z_stream strm;
  strm.zalloc   = Z_NULL;
  strm.zfree    = Z_NULL;
  strm.opaque   = Z_NULL;
  strm.avail_in = 0;
  strm.next_in  = Z_NULL;

  int ret;
  ret = inflateInit(&strm);
  if (ret != Z_OK)
    return false;

  /* seek to the start of the stream */
  input.seekg(0);

  do
  {
    char bin [65535];
    char bout[65535];

    /* fill the buffer */
    input.read(bin, sizeof(bin));
    strm.avail_in = input.gcount();
    strm.next_in  = (unsigned char*)bin;
    if (strm.avail_in == 0)
      break;

    /* inflate the data and append it */
    do
    {
      strm.avail_out = sizeof(bout);
      strm.next_out  = (unsigned char*)bout;

      ret = inflate(&strm, Z_NO_FLUSH);
      switch(ret)
      {
        case Z_STREAM_ERROR:
        case Z_NEED_DICT   :
        case Z_DATA_ERROR  :
        case Z_MEM_ERROR   :
          inflateEnd(&strm);
          return false;
      }

      output.write(bout, sizeof(bout) - strm.avail_out);
    }
    while (strm.avail_out == 0);
  }
  while (ret != Z_STREAM_END);

  inflateEnd(&strm);
  return true;
}
