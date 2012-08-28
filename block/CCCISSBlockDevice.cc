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

#include "CCCISSBlockDevice.h"

#include "common/CCommon.h"
#include <dirent.h>
#include <string>
#include <pcrecpp.h>

#include <stdio.h>

void CCCISSBlockDevice::Enumerate(IBlockDevice::Map &map)
{
  DIR *dh = opendir("/dev/cciss");
  if (!dh)
    return;

  pcrecpp::RE reDev("c\\d+d\\d+");

  while(struct dirent *dir = readdir(dh))
  {
    if (!reDev.FullMatch(dir->d_name))
      continue;

    std::string device = "/dev/cciss/";
    device.append(dir->d_name);

    CCCISSBlockDevice *dev = new CCCISSBlockDevice(device);
    map.insert(IBlockDevice::MapPair(device, dev));
  }

  closedir(dh); 
}

CCCISSBlockDevice::CCCISSBlockDevice(const std::string &device) :
  m_device(device),
  m_NA    ("N/A" )
{
  Refresh();
}

bool CCCISSBlockDevice::Refresh()
{
  std::string result;
  if (!CCommon::RunCommand(result, (CCommon::GetBasePath() + "/bin/cciss_vol_status"), m_device.c_str(), NULL))
    return false;

  if (!pcrecpp::RE("/dev/cciss/c\\d+d\\d+:\\s+\\((.+)\\)\\s+.+:\\s+(.+)\\.").PartialMatch(result, &m_model, &m_status))
    return false;

  return true;
}

bool CCCISSBlockDevice::IsOK()
{
  if (!Refresh())
    return false;
  
  return m_status == "OK";
}
