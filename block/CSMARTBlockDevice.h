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

#ifndef _ISMARTBLOCKDEVICE_H_
#define _ISMARTBLOCKDEVICE_H_

#include "IBlockDevice.h"

class CSMARTBlockDevice : public IBlockDevice
{
  public:
    CSMARTBlockDevice(const std::string &device, const std::string &driver);

    static void Enumerate(IBlockDevice::Map &map);

    virtual const char        *GetType        () { return "SMART"   ; }
    virtual bool               Refresh        ();
    virtual const std::string &GetError       () { return m_error   ; }
    virtual const std::string &GetDevName     () { return m_device  ; }
    virtual const std::string &GetModel       () { return m_model   ; }
    virtual const std::string &GetFirmware    () { return m_firmware; }
    virtual const std::string &GetSerialNumber() { return m_serial  ; }
    virtual bool               IsOK           ();

  private:
    std::string m_error;
    std::string m_device;
    std::string m_driver;
    std::string m_model;
    std::string m_serial;
    std::string m_firmware;
};

#endif
