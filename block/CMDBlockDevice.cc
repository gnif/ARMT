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

#include "CMDBlockDevice.h"

#include "common/CCommon.h"
#include <string>
#include <pcrecpp.h>
#include <dirent.h>

#include <stdio.h>

void CMDBlockDevice::Enumerate(IBlockDevice::Map &map)
{
  FILE *fp = fopen("/proc/mdstat", "r");
  if (!fp)
    return;

  std::string mdstat;
  while(!feof(fp))
  {
    char   buffer[1024];
    size_t length = fread(buffer, 1, sizeof(buffer), fp);
    mdstat.append(buffer, length);
  }
  fclose(fp);

  std::string node;
  pcrecpp::StringPiece input(mdstat);
  pcrecpp::RE_Options  options;
  options.set_multiline(true);

  pcrecpp::RE re("^(md\\d+)\\s*:\\s*", options);

  while (re.FindAndConsume(&input, &node))
  {
    std::string device = "/dev/";
    device.append(node);

    CMDBlockDevice *dev = new CMDBlockDevice(device, node);
    map.insert(IBlockDevice::MapPair(node, dev));
  }
}

CMDBlockDevice::CMDBlockDevice(const std::string &device, const std::string &node) :
  m_device(device),
  m_node  (node  ),
  m_NA    ("N/A" )
{
  Refresh();
}

bool CMDBlockDevice::Refresh()
{
  std::string path = "/sys/block/";
  path.append(m_node);
  path.append("/slaves");

  DIR *dh = opendir(path.c_str());
  if (!dh)
    return false;

  m_model.clear();
  while(struct dirent *dir = readdir(dh))
  {
    if (dir->d_name[0] == '.')
      continue;

    m_model.append(dir->d_name);
    m_model.append(" ");
  }
  CCommon::Trim(m_model);

  closedir(dh);
  return true;
}

bool CMDBlockDevice::IsOK()
{
  FILE *fp = fopen("/proc/mdstat", "r");
  if (!fp)
    return false;

  std::string mdstat;
  while(!feof(fp))
  {
    char   buffer[1024];
    size_t length = fread(buffer, 1, sizeof(buffer), fp);
    mdstat.append(buffer, length);
  }
  fclose(fp);

  std::string node;
  pcrecpp::StringPiece input(mdstat);
  pcrecpp::RE_Options  options;
  options.set_multiline(true);

  std::string exp = "^";
  exp.append(m_node);
  exp.append("\\s*:.*\\n.*\\[([UF_]+)\\]$");

  std::string match;
  if (!pcrecpp::RE(exp, options).PartialMatch(mdstat, &match))
    return false;

  for(unsigned int i = 0; i < match.length(); ++i)
    if (match[i] != 'U')
      return false;

  return true;
}
