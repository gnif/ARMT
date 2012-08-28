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

#ifndef _CPCIINFO_H_
#define _CPCIINFO_H_

#include <stdint.h>
#include <string>
#include <vector>

class CPCIInfo
{
  public:
    class CDevice
    {
      friend class CPCIInfo;
    
      public:
        const uint16_t GetClass     () { return m_class     ; }
        const uint16_t GetVendorID  () { return m_vendorID  ; }
        const uint16_t GetDeviceID  () { return m_deviceID  ; }

        const std::string& GetClassName () { return m_className ; }
#if defined(HAS_PCILIB)
        const std::string& GetVendorName() { return m_vendorName; }
        const std::string& GetDeviceName() { return m_deviceName; }
#endif
      private:
        uint16_t m_class;
        uint16_t m_vendorID;
        uint16_t m_deviceID;

        std::string m_className;
#if defined(HAS_PCILIB)        
        std::string m_vendorName;
        std::string m_deviceName;
#endif
    };
    
    typedef std::vector<CDevice>            DeviceList;
    typedef std::vector<CDevice>::iterator  DeviceListIterator;
    
    static void              ClearCache();
    static const DeviceList& GetDeviceList(); 

  protected:
  private:
    static bool       m_gotDeviceList;
    static DeviceList m_deviceList;
};

#endif // _CPCIINFO_H_
