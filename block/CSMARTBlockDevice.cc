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

#include "CSMARTBlockDevice.h"
#include "common/CCommon.h"

#include <stdio.h>
#include <pcrecpp.h>

#include <sstream>
#include <string>

void CSMARTBlockDevice::Enumerate(IBlockDevice::Map &map)
{
  /* scan for disks using smartctl */
  std::string result;
  if (CCommon::RunCommand(result, (CCommon::GetBasePath() + "/bin/smartctl"), "--scan-open", NULL))
  {
    std::stringstream ss(result);
    std::string line;
    while(std::getline(ss, line, '\n')) {
      std::stringstream parser(line);

      bool first = true;
      std::string device, driver, word;
      while(std::getline(parser, word, ' ')) {
        /* first column is the device */
        if (first)
        {
          /* failure to open the device */
          if (word == "#")
            continue;

          device.assign(word);
          first = false;
          continue;
        }

        /* look for the driver to use */
        if (word == "-d")
        {
            std::getline(parser, driver, ' ');
            break;
        }
      }

      if (driver.empty())
        continue;

      CSMARTBlockDevice *dev = new CSMARTBlockDevice(device, driver);
      map.insert(IBlockDevice::MapPair(device, dev));
    }
  }
}

CSMARTBlockDevice::CSMARTBlockDevice(const std::string &device, const std::string &driver) :
  m_device(device),
  m_driver(driver)
{
  Refresh();
}

bool CSMARTBlockDevice::Refresh()
{
  std::string result;
  CCommon::RunCommand(result, (CCommon::GetBasePath() + "/bin/smartctl"), "-d", m_driver.c_str(), m_device.c_str(), "-i", NULL);

  if (pcrecpp::RE("Permission denied").PartialMatch(result))
  {
    m_error      =
      m_model    = 
      m_serial   =
      m_firmware = "Permission denied";
    return false;
  }

  pcrecpp::RE_Options options;
  options.set_multiline(true);

  if (m_driver == "sat")
  {
    pcrecpp::RE("^Device Model:\\s+(.+)$"    , options).PartialMatch(result, &m_model   );
    pcrecpp::RE("^Serial Number:\\s+(.+)$"   , options).PartialMatch(result, &m_serial  );
    pcrecpp::RE("^Firmware Version:\\s+(.+)$", options).PartialMatch(result, &m_firmware);
  } else
  if (m_driver == "scsi")
  {
    std::string temp;

    pcrecpp::RE("^Vendor:\\s+(.+)$"       , options).PartialMatch(result, &m_model   );
    pcrecpp::RE("^Product:\\s+(.+)$"      , options).PartialMatch(result, &temp      );
    pcrecpp::RE("^Serial number:\\s+(.+)$", options).PartialMatch(result, &m_serial  );
    pcrecpp::RE("^Revision:\\s+(.+)$"     , options).PartialMatch(result, &m_firmware);

    CCommon::Trim(m_model);
    CCommon::Trim(temp   );
    m_model.append(" ");
    m_model.append(temp);
  }

  CCommon::Trim(m_model   );
  CCommon::Trim(m_serial  );
  CCommon::Trim(m_firmware);

  if (m_model   .empty()) m_model    = "UNKNOWN";
  if (m_serial  .empty()) m_serial   = "UNKNOWN";
  if (m_firmware.empty()) m_firmware = "UNKNOWN";

  return true;
}

bool CSMARTBlockDevice::IsOK()
{
  std::string result, status;
  CCommon::RunCommand(result, (CCommon::GetBasePath() + "/bin/smartctl"), "-d", m_driver.c_str(), m_device.c_str(), "-H", NULL);

  pcrecpp::RE_Options options;
  options.set_multiline(true);
  pcrecpp::RE("^SMART\\s+.+:\\s+(.+)$", options).PartialMatch(result, &status);
  CCommon::Trim(status);

  if (status == "OK" || status == "PASSED")
    return true;

  return false;
}

