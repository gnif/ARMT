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

#ifndef _CFSVERIFIER_H_
#define _CFSVERIFIER_H_

#include <string>
#include <map>
#include <vector>

#include <sys/stat.h>

class CFSVerifier
{
  public:
    enum DiffType
    {
      DT_MODIFIED = 0,
      DT_MISSING  = 1,
      DT_NEW      = 2
    };

    struct DiffRecord
    {
      std::string   m_path;
      enum DiffType m_type;
    };

    typedef std::vector<DiffRecord> DiffList;


    ~CFSVerifier();

    void AddExclude(const std::string &path);
    bool AddPath(std::string path, const bool recurse);
    void Scan();
    bool Save(const std::string &filename);
    bool Diff(const std::string &filename, DiffList &result);

  private:
    typedef std::vector<std::string                > StringList;

    typedef std::map   <std::string, bool          > PathMap;
    typedef std::pair  <std::string, bool          > PathPair;
    typedef std::map   <std::string, unsigned char*> FileMap;
    typedef std::pair  <std::string, unsigned char*> FilePair;

    StringList m_exclude;
    PathMap    m_paths;
    FileMap    m_files;
};

#endif
