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

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/utsname.h>
#include <fstream>

#include "common/CDNS.h"
#include "common/CPCIInfo.h"
#include "common/CProcInfo.h"
#include "common/CCommon.h"
#include "common/CHTTP.h"

#include "fs/CFSVerifier.h"

#include "block/CBlockEnumerator.h"

/* we wrap the libc version to avoid shared linking */
CDNS DNS;
static struct hostent *_hostent = NULL;
extern "C" {
  struct hostent *__wrap_gethostbyname(const char *host)
  {
    if (_hostent)
      DNS.Free(_hostent);
    _hostent = DNS.GetHostByName(host);
    return _hostent;
  }
}

void BlockDeviceCheck()
{
  IBlockDevice::Map map = CBlockEnumerator::Enumerate();
  for(IBlockDevice::Map::iterator it = map.begin(); it != map.end(); ++it)
  {
    const std::string &error = it->second->GetError();
    if (!error.empty())
    {
      printf(
        "======== (%s) ========\n"
        "  Device: %s\n"
        "   Error: %s\n",
        it->second->GetType   (),
        it->second->GetDevName().c_str(),
        error                   .c_str()
      );
      continue;
    }

    printf(
      "======== (%s) ========\n"
      "  Device: %s\n"
      "   Model: %s\n"
      "  Serial: %s\n"
      "Firmware: %s\n"
      "  Status: %s\n",
      it->second->GetType        (),
      it->second->GetDevName     ().c_str(),
      it->second->GetModel       ().c_str(),
      it->second->GetSerialNumber().c_str(),
      it->second->GetFirmware    ().c_str(),
      it->second->IsOK           () ? "OK" : "FAILURE"
    );
  }
}

void FSCheck()
{
  CFSVerifier fs;
  fs.AddExclude("/boot/lost+found");
  fs.AddExclude("/usr/src");

  /* get the running kernel version and add the module path for it */
  struct utsname details;
  uname(&details);
  std::string modules = "/lib/modules/";
  modules.append(details.release);
  fs.AddPath(modules, true);

  /* exclude all other module paths */
  fs.AddExclude("/lib/modules");

  /* protect critcal paths */
  fs.AddPath("/boot", true);
  fs.AddPath("/bin" , true);
  fs.AddPath("/sbin", true);
  fs.AddPath("/lib" , true);

  /* scan for files and hash them */
  fs.Scan();

  /* save the file listing */
  {
    std::fstream file("files.dump", std::fstream::out | std::fstream::trunc | std::fstream::binary);
    fs.Save(file);
    file.close();
  }

  /* diff the scanned list against the saved file */
  CFSVerifier::DiffList diff;
  {
    std::fstream file("files.dump", std::fstream::in | std::fstream::binary);
    fs.Diff(file, diff);
  }

  for(CFSVerifier::DiffList::const_iterator it = diff.begin(); it != diff.end(); ++it)
  {
    const char *status = "";
    switch(it->m_type)
    {
      case CFSVerifier::DT_MODIFIED: status = "Modified File"; break;
      case CFSVerifier::DT_MISSING : status = "Missing File" ; break;
      case CFSVerifier::DT_NEW     : status = "New File"     ; break;
    }
    printf("%s - %s\n", it->m_path.c_str(), status);
  }
}

int main(int argc, char *argv[])
{
  /* must be called first */
  CCommon::Initialize(argc, argv);

  /* DNS resolver must be setup next so the wrapper works */
  DNS.AddResolver("8.8.8.8"       );  /* Google  */
  DNS.AddResolver("8.8.4.4"       );  /* Google  */
  DNS.AddResolver("208.67.222.222");  /* OpenDNS */
  DNS.AddResolver("208.67.222.220");  /* OpenDNS */

  FSCheck();
  return 0;

  CHTTP http;
  std::string buffer;
  http.SetHeader("Host"           , argv[1]);
  http.SetHeader("User-Agent"     , "ARMT");
  http.SetHeader("Connection"     , "close");
  http.SetHeader("Accept"         , "text/plain");
  http.SetHeader("Accept-Encoding", ""); 

  uint16_t         error;
  CHTTP::HeaderMap headers;
  std::string      body;

  if (http.Connect(argv[1], 443, true) && http.PerformRequest("GET", "/", error, headers, body))
  {
    printf("%u\n", error);
    printf("%s\n", headers["date"].c_str());
    printf("%s\n", body.c_str());
  }

  if (_hostent)
    DNS.Free(_hostent);

//  BlockDeviceCheck();
  return 0;


#if 0
  CPCIInfo::DeviceList devices = CPCIInfo::GetDeviceList();
  for(CPCIInfo::DeviceListIterator itt = devices.begin(); itt != devices.end(); ++itt)
  {
    printf("[0x%04hx|0x%04hx:0x%04hx] %s"
#if defined(HAS_PCILIB)
      " %s - %s"
#endif
      "\n",
      itt->GetClass(),
      itt->GetVendorID(),
      itt->GetDeviceID(),
      itt->GetClassName().c_str()
#if defined(HAS_PCILIB)
      ,
      itt->GetVendorName().c_str(),
      itt->GetDeviceName().c_str()
#endif
    );
  }
  
  return 0;

  CProcInfo::ProcessList list = CProcInfo::GetProcessList();
  for(CProcInfo::ProcessListIterator itt = list.begin(); itt != list.end(); ++itt)
  {  
    printf(
      "PID    : %d\n"
      "EXE    : %s\n"
      "COMM   : %s\n"
      "CMDLINE: %s\n",
      itt->GetPID(),
      itt->GetExe    ().c_str(),
      itt->GetComm   ().c_str(),
      itt->GetCmdLine().c_str()
    );
    
    CProcInfo::BoundList bound = itt->GetBoundList();
    for(CProcInfo::BoundListIterator itt2 = bound.begin(); itt2 != bound.end(); ++itt2)
    {
      if (itt2->GetType() == CProcInfo::PORT_TYPE_UNIX)
           printf("  BOUND: %s(%s)\n"   , CProcInfo::PortTypeToString(itt2->GetType()), itt2->GetPath().c_str());
      else printf("  BOUND: %s(%s:%u)\n", CProcInfo::PortTypeToString(itt2->GetType()), CProcInfo::IPToString(itt2->GetIP()).c_str(), itt2->GetPort());
    }
    
    printf("\n");
  }
#endif
}
