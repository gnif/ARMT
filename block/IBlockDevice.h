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

#ifndef _IBLOCKDEVICE_H_
#define _IBLOCKDEVICE_H_

#include <map>
#include <string>

class IBlockDevice
{
  public:
    /**
      * Typedefs for application usage
      */
    typedef std::map <std::string, IBlockDevice *> Map;
    typedef std::pair<std::string, IBlockDevice *> MapPair;

    /**
      * Returns the block device type (eg, IBlockDevice)
      */
    virtual const char *GetType() = 0;

    /**
      * Refreshes device information
      * @return true if refresh was successfull
      */
    virtual bool Refresh() = 0;

    /**
      * Get the error if there is any
      */
    virtual const std::string &GetError() = 0;

    /**
      * Returns the device's dev name
      */
    virtual const std::string &GetDevName() = 0;

    /**
      * Returns the device model
      */
    virtual const std::string &GetModel() = 0;

    /**
      * Returns the device serial number
      */
    virtual const std::string &GetSerialNumber() = 0;

    /**
      * Returns the device firmware version
      */
    virtual const std::string &GetFirmware() = 0;

    /**
      * Return's true if the device reports that it is OK (ie: S.M.A.R.T. status)
      */
    virtual bool IsOK() = 0;
};

#endif
