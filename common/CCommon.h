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

#ifndef _CCOMMON_H_
#define _CCOMMON_H_

#include <stdint.h>
#include <string>
#include <vector>

class CCommon
{
  public:
    typedef std::vector<std::string>                 StringList;
    typedef std::vector<std::string>::iterator       StringListIterator;
    typedef std::vector<std::string>::const_iterator StringListConstIterator;

    static void  Initialize(const int argc, char* const argv[]);

    static bool        IsBE() { return m_isBE; }
    static void        Trim    (std::string &s);
    static std::string IntToStr(int value, int base = 10);
    static std::string StrToLower(const std::string &string);

    static const std::string &GetExePath () { return m_exePath ; }
    static const std::string &GetBasePath() { return m_basePath; }

    static bool IsFile     (const std::string &path);
    static bool IsDir      (const std::string &path);
    static bool WriteBuffer(const std::string &path, const void *buffer, const size_t size);
    static bool WriteExe   (const std::string &path, const void *buffer, const size_t size);

    static bool SimpleReadBool  (const std::string &path, bool        &dest);
    static bool SimpleReadStr   (const std::string &path, std::string &dest);
    static bool SimpleReadInt32 (const std::string &path, int32_t     &dest, const int base = 10);
    static bool SimpleReadInt16 (const std::string &path, int16_t     &dest, const int base = 10);
    static bool SimpleReadUInt32(const std::string &path, uint32_t    &dest, const int base = 10);
    static bool SimpleReadUInt16(const std::string &path, uint16_t    &dest, const int base = 10);

    static bool RunCommand(std::string &result, const std::string &cmd, ...) __attribute__ ((sentinel));
  private:
    static bool         m_isBE;
    static std::string  m_exePath;
    static std::string  m_basePath;
};

#endif // _CCOMMON_H_
