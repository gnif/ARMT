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

#include "CBlockEnumerator.h"

#include "common/CCommon.h"
#include "CSMARTBlockDevice.h"
#include "CCCISSBlockDevice.h"
#include "CMDBlockDevice.h"

IBlockDevice::Map CBlockEnumerator::Enumerate()
{
  IBlockDevice::Map map;
  CSMARTBlockDevice::Enumerate(map);
  CCCISSBlockDevice::Enumerate(map);
  CMDBlockDevice   ::Enumerate(map);
  return map;
}
