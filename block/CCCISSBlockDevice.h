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

#ifndef _ICCISSBLOCKDEVICE_H_
#define _ICCISSBLOCKDEVICE_H_

#include "IBlockDevice.h"

class CCCISSBlockDevice : public IBlockDevice
{
  public:
    CCCISSBlockDevice(const std::string &device);

    static void Enumerate(IBlockDevice::Map &map);

    virtual const char        *GetType        () { return "CCISS"; }
    virtual bool               Refresh        ();
    virtual const std::string &GetError       () { return m_error   ; }
    virtual const std::string &GetDevName     () { return m_device  ; }
    virtual const std::string &GetModel       () { return m_model   ; }
    virtual const std::string &GetFirmware    () { return m_NA      ; }
    virtual const std::string &GetSerialNumber() { return m_NA      ; }
    virtual bool               IsOK           ();

  private:
    std::string m_error;
    std::string m_device;
    std::string m_model;
    std::string m_status;
    std::string m_NA;
};

#endif
