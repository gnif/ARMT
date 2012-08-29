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

#include "CFSVerifier.h"
#include "common/CCompress.h"

#include "polarssl/md5.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>

#include <sstream>
#include <fstream>

CFSVerifier::~CFSVerifier()
{
  /* free records */
  while(!m_files.empty())
  {
    delete[] m_files.begin()->second;
    m_files.erase(m_files.begin());
  }
}

void CFSVerifier::AddExclude(const std::string &path)
{
  m_exclude.push_back(path);
}

bool CFSVerifier::AddPath(std::string path, const bool recurse)
{
  /* ensure the path exists */
  struct stat st;
  if (stat(path.c_str(), &st) < 0 || !S_ISDIR(st.st_mode))
    return false;

  /* resolve the path to a realpath */
  char *resolved = realpath(path.c_str(), NULL);
  path.assign(resolved);
  free(resolved);

  /* check if the path is in the exclude list */
  for(StringList::const_iterator it = m_exclude.begin(); it != m_exclude.end(); ++it)
  {
    if (strncmp(it->c_str(), path.c_str(), it->length()) == 0)
      return false;
  }

  /* dont insert duplicates */
  if (m_paths.find(path) != m_paths.end())
    return false;

  /* add the path */
  m_paths.insert(PathPair(path, recurse));

  /* check for recursion */
  if (recurse)
  {
    DIR *dh = opendir(path.c_str());
    while(struct dirent *dir = readdir(dh))
    {
      if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0)
        continue;

      std::string next = path;
      next.append("/");
      next.append(dir->d_name);

      AddPath(next, true);
    }
    closedir(dh);
  }

  return true;
}

void CFSVerifier::Scan()
{
  for(PathMap::iterator it = m_paths.begin(); it != m_paths.end(); ++it)
  {
    DIR *dh = opendir(it->first.c_str());
    if (!dh)
      continue;

    while(struct dirent *dir = readdir(dh))
    {
      if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0)
        continue;

      std::string path = it->first;
      path.append("/");
      path.append(dir->d_name);

      struct stat st;
      if (stat(path.c_str(), &st) < 0)
        continue;

      if (!S_ISREG(st.st_mode))
        continue;

      unsigned char *digest = new unsigned char[16];
      if (md5_file(path.c_str(), digest) != 0)
      {
        delete[] digest;
        continue;
      }

      m_files.insert(FilePair(path, digest));
    }
    closedir(dh);
  }
}

bool CFSVerifier::Save(const std::string &filename)
{
  std::stringstream ss;
  for(FileMap::const_iterator it = m_files.begin(); it != m_files.end(); ++it)
  {
    uint16_t length = it->first.length();
    ss.write((const char *)&length   , sizeof(length));
    ss.write(it->first.c_str()       , length        );
    ss.write((const char *)it->second, 16            );
  }

  std::fstream file;
  file.open(
    filename.c_str(),
    std::fstream::out | std::fstream::trunc | std::fstream::binary
  );

  if (!file.good())
    return false;

  bool result = CCompress::Deflate(ss, file);
  file.close();

  return result;
}

bool CFSVerifier::Diff(const std::string &filename, DiffList &result)
{
  std::fstream file;
  file.open(
    filename.c_str(),
    std::fstream::in | std::fstream::binary
  );

  if (!file.good())
    return false;

  std::stringstream ss;
  if (!CCompress::Inflate(file, ss))
  {
    file.close();
    return false;
  }

  file.close();

  FileMap  compare;
  uint16_t length;
  while(!ss.eof())
  {
    ss.read((char *)&length, sizeof(length));
    if (ss.gcount() < (std::streamsize)sizeof(length))
      return false;

    char buffer[length];
    ss.read((char *)&buffer, length);
    if (ss.gcount() < (std::streamsize)length)
      return false;

    std::string path;
    path.assign(buffer, length);

    unsigned char *hash = new unsigned char[16];
    ss.read((char *)hash, 16);
    if (ss.gcount() < (std::streamsize)16)
      return false;

    compare.insert(FilePair(path, hash));

    FileMap::const_iterator it = m_files.find(path);
    if (it == m_files.end())
    {
      DiffRecord record;
      record.m_path = path;
      record.m_type = DT_MISSING;
      result.push_back(record);
      continue;
    }

    if (memcmp(it->second, hash, 16) != 0)
    {
      DiffRecord record;
      record.m_path = path;
      record.m_type = DT_MODIFIED;
      result.push_back(record);
      continue;
    }
  }

  /* look for new files */
  for(FileMap::const_iterator it = m_files.begin(); it != m_files.end(); ++it)
  {
    if (compare.find(it->first) == compare.end())
    {
      DiffRecord record;
      record.m_path = it->first;
      record.m_type = DT_NEW;
      result.push_back(record);
    }
  }

  /* free loaded records */
  while(!compare.empty())
  {
    delete[] compare.begin()->second;
    compare.erase(compare.begin());
  }

  return true;
}

