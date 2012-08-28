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

#include "CPCIInfo.h"

#if defined(HAS_LIBPCI)
extern "C"{
  #include <pci/pci.h>
}
#else
  #include "CCommon.h"
  #include <dirent.h>
#endif

#include <stdio.h>

/* static definitions */
bool      CPCIInfo::m_gotDeviceList = false;
CPCIInfo::DeviceList  CPCIInfo::m_deviceList;

void CPCIInfo::ClearCache()
{
  m_gotDeviceList = false;
  m_deviceList.empty();
}

const CPCIInfo::DeviceList& CPCIInfo::GetDeviceList()
{
  if (m_gotDeviceList)
    return m_deviceList;
  m_gotDeviceList = true;
 
#if defined(HAS_LIBPCI)

  struct pci_access *pacc = pci_alloc();
  pci_init(pacc);
  pci_scan_bus(pacc);
  for(struct pci_dev *p = pacc->devices; p; p = p->next) {
    pci_fill_info(p,PCI_FILL_IDENT);
    
    char classbuf[512], venbuf[512], devbuf[512];
    pci_lookup_name(pacc, classbuf, sizeof(classbuf), PCI_LOOKUP_CLASS , p->device_class);
    pci_lookup_name(pacc, venbuf  , sizeof(venbuf  ), PCI_LOOKUP_VENDOR, p->vendor_id   );
    pci_lookup_name(pacc, devbuf  , sizeof(devbuf  ), PCI_LOOKUP_DEVICE, p->vendor_id, p->device_id);    
    
    CDevice device;
    device.m_class      = p->device_class;
    device.m_vendorID   = p->vendor_id;
    device.m_deviceID   = p->device_id;
    device.m_className  = classbuf;
    device.m_vendorName = venbuf;
    device.m_deviceName = devbuf;
    
    m_deviceList.push_back(device);
  }
  pci_cleanup(pacc);

#else

  DIR *dh = opendir("/sys/bus/pci/devices");
  if (!dh)
    return m_deviceList;

  while(struct dirent *dir = readdir(dh))
  {
    if (dir->d_name[0] == '.')
      continue;

    std::string path = "/sys/bus/pci/devices/";
    path.append(dir->d_name);

    CDevice device;
    uint32_t classID;
    if (!CCommon::SimpleReadUInt32(path + "/class" , classID          , 16)) continue;
    if (!CCommon::SimpleReadUInt16(path + "/vendor", device.m_vendorID, 16)) continue;
    if (!CCommon::SimpleReadUInt16(path + "/device", device.m_deviceID, 16)) continue;

    device.m_class = (classID >> 8) & 0xFFFF;

    switch(device.m_class)
    {
      case 0x0000: device.m_className = "Non-VGA unclassified device"             ; break;
      case 0x0001: device.m_className = "VGA compatible unclassified device"      ; break;

      case 0x0100: device.m_className = "SCSI storage controller"                 ; break;
      case 0x0101: device.m_className = "IDE interface"                           ; break;
      case 0x0102: device.m_className = "Floppy disk controller"                  ; break;
      case 0x0103: device.m_className = "IPI bus controller"                      ; break;
      case 0x0104: device.m_className = "RAID bus controller"                     ; break;
      case 0x0105: device.m_className = "ATA controller"                          ; break;
      case 0x0106: device.m_className = "SATA controller"                         ; break;
      case 0x0107: device.m_className = "Serial Attached SCSI controller"         ; break;
      case 0x0108: device.m_className = "Non-Volatile memory controller"          ; break;
      case 0x0180: device.m_className = "Mass storage controller"                 ; break;

      case 0x0200: device.m_className = "Ethernet controller"                     ; break;
      case 0x0201: device.m_className = "Token ring network controller"           ; break;
      case 0x0203: device.m_className = "FDDI network controller"                 ; break;
      case 0x0204: device.m_className = "ISDN controller"                         ; break;
      case 0x0205: device.m_className = "WorldFip controller"                     ; break;
      case 0x0206: device.m_className = "PiCMG controller"                        ; break;
      case 0x0280: device.m_className = "Network controller"                      ; break;

      case 0x0300: device.m_className = "VGA compatible controller"               ; break;
      case 0x0301: device.m_className = "XGA compatible controller"               ; break;
      case 0x0302: device.m_className = "3D controller"                           ; break;
      case 0x0380: device.m_className = "Display controller"                      ; break;

      case 0x0400: device.m_className = "Multimedia video controller"             ; break;
      case 0x0401: device.m_className = "Multimedia audio controller"             ; break;
      case 0x0402: device.m_className = "Computer telephony device"               ; break;
      case 0x0403: device.m_className = "Audio device"                            ; break;
      case 0x0480: device.m_className = "Multimedia controller"                   ; break;

      case 0x0500: device.m_className = "RAM memory"                              ; break;
      case 0x0501: device.m_className = "FLASH memory"                            ; break;
      case 0x0580: device.m_className = "Memory controller"                       ; break;

      case 0x0600: device.m_className = "Host bridge"                             ; break;
      case 0x0601: device.m_className = "ISA bridge"                              ; break;
      case 0x0602: device.m_className = "EISA bridge"                             ; break;
      case 0x0603: device.m_className = "MicroChannel bridge"                     ; break;
      case 0x0604: device.m_className = "PCI bridge"                              ; break;
      case 0x0605: device.m_className = "PCMCIA bridge"                           ; break;
      case 0x0606: device.m_className = "NuBus bridge"                            ; break;
      case 0x0607: device.m_className = "CardBus bridge"                          ; break;
      case 0x0608: device.m_className = "RACEway bridge"                          ; break;
      case 0x0609: device.m_className = "Semi-transparent PCI-to-PCI bridge"      ; break;
      case 0x060a: device.m_className = "InfiniBand to PCI host bridge"           ; break;
      case 0x0680: device.m_className = "Bridge"                                  ; break;

      case 0x0700: device.m_className = "Serial controller"                       ; break;
      case 0x0701: device.m_className = "Parallel controller"                     ; break;
      case 0x0702: device.m_className = "Multiport serial controller"             ; break;
      case 0x0703: device.m_className = "Modem"                                   ; break;
      case 0x0704: device.m_className = "GPIB controller"                         ; break;
      case 0x0705: device.m_className = "Smart Card controller"                   ; break;
      case 0x0780: device.m_className = "Communication controller"                ; break;

      case 0x0800: device.m_className = "PIC"                                     ; break;
      case 0x0801: device.m_className = "DMA controller"                          ; break;
      case 0x0802: device.m_className = "Timer"                                   ; break;
      case 0x0803: device.m_className = "RTC"                                     ; break;
      case 0x0804: device.m_className = "PCI Hot-plug controller"                 ; break;
      case 0x0805: device.m_className = "SD Host controller"                      ; break;
      case 0x0806: device.m_className = "IOMMU"                                   ; break;
      case 0x0880: device.m_className = "System peripheral"                       ; break;

      case 0x0900: device.m_className = "Keyboard controller"                     ; break;
      case 0x0901: device.m_className = "Digitizer Pen"                           ; break;
      case 0x0902: device.m_className = "Mouse controller"                        ; break;
      case 0x0903: device.m_className = "Scanner controller"                      ; break;
      case 0x0904: device.m_className = "Gameport controller"                     ; break;
      case 0x0980: device.m_className = "Input device controller"                 ; break;

      case 0x0a00: device.m_className = "Generic Docking Station"                 ; break;
      case 0x0a80: device.m_className = "Docking Station"                         ; break;

      case 0x0b00: device.m_className = "386"                                     ; break;
      case 0x0b01: device.m_className = "486"                                     ; break;
      case 0x0b02: device.m_className = "Pentium"                                 ; break;

      case 0x0b10: device.m_className = "Alpha"                                   ; break;
      case 0x0b20: device.m_className = "Power PC"                                ; break;
      case 0x0b30: device.m_className = "MIPS"                                    ; break;
      case 0x0b40: device.m_className = "Co-processor"                            ; break;

      case 0x0c00: device.m_className = "FireWire (IEEE 1394)"                    ; break;
      case 0x0c01: device.m_className = "ACCESS Bus"                              ; break;
      case 0x0c02: device.m_className = "SSA"                                     ; break;
      case 0x0c03: device.m_className = "USB controller"                          ; break;
      case 0x0c04: device.m_className = "Fibre Channel"                           ; break;
      case 0x0c05: device.m_className = "SMBus"                                   ; break;
      case 0x0c06: device.m_className = "InfiniBand"                              ; break;
      case 0x0c07: device.m_className = "IPMI SMIC interface"                     ; break;
      case 0x0c08: device.m_className = "SERCOS interface"                        ; break;
      case 0x0c09: device.m_className = "CANBUS"                                  ; break;

      case 0x0d00: device.m_className = "IRDA controller"                         ; break;
      case 0x0d01: device.m_className = "Consumer IR controller"                  ; break;
      case 0x0d10: device.m_className = "RF controller"                           ; break;
      case 0x0d11: device.m_className = "Bluetooth"                               ; break;
      case 0x0d12: device.m_className = "Broadband"                               ; break;
      case 0x0d20: device.m_className = "802.1a controller"                       ; break;
      case 0x0d21: device.m_className = "802.1b controller"                       ; break;
      case 0x0d80: device.m_className = "Wireless controller"                     ; break;

      case 0x0e00: device.m_className = "I2O"                                     ; break;

      case 0x0f00: device.m_className = "Satellite TV controller"                 ; break;
      case 0x0f01: device.m_className = "Satellite audio communication controller"; break;
      case 0x0f02: device.m_className = "Satellite video communication controller"; break;
      case 0x0f03: device.m_className = "Satellite voice communication controller"; break;
      case 0x0f04: device.m_className = "Satellite data communication controller" ; break;

      case 0x1000: device.m_className = "Network and computing encryption device" ; break;
      case 0x1010: device.m_className = "Entertainment encryption device"         ; break;
      case 0x1080: device.m_className = "Encryption controller"                   ; break;

      case 0x1100: device.m_className = "DPIO module"                             ; break;
      case 0x1101: device.m_className = "Performance counters"                    ; break;
      case 0x1110: device.m_className = "Communication synchronizer"              ; break;
      case 0x1120: device.m_className = "Signal processing management"            ; break;
      case 0x1180: device.m_className = "Signal processing controller"            ; break;
    }

    m_deviceList.push_back(device);
  }

  closedir(dh);

#endif
  return m_deviceList;
}
