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

#ifndef _CPROCINFO_H_
#define _CPROCINFO_H_

#include <stdint.h>
#include <string>
#include <vector>

#include <stdio.h>

class CProcInfo
{
    friend class CProcess;

    public:    
    enum PortType
    {
      PORT_TYPE_INVALID = -1,
      
      PORT_TYPE_TCP,
      PORT_TYPE_UDP,
      PORT_TYPE_UNIX,
      
      PORT_TYPE_COUNT
    };
    
    static const char* PortTypeToString(enum PortType type)
    {
      switch(type) {
        case PORT_TYPE_INVALID: return "PORT_TYPE_INVALID";      
        case PORT_TYPE_TCP    : return "PORT_TYPE_TCP";
        case PORT_TYPE_UDP    : return "PORT_TYPE_UDP";
        case PORT_TYPE_UNIX   : return "PORT_TYPE_UNIX";
        case PORT_TYPE_COUNT  : return "PORT_TYPE_COUNT";
      }
      return "";
    }
    
    static std::string IPToString(unsigned int ip)
    {
      char result[16];
      sprintf(result, "%d.%d.%d.%d",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >>  8) & 0xFF,
        (ip >>  0) & 0xFF
      );
      return result;
    }
    
      class CBound
      {
        friend class CProcInfo;
        public:
        const uint16_t      GetUID  () { return m_uid ;  }
        const enum PortType GetType () { return m_type;  }
        const unsigned int  GetIP   () { return m_ip  ;  }
        const uint16_t      GetPort () { return m_port;  }
        const std::string&  GetPath () { return m_path;  }
        
      private:
        unsigned int    m_socket;
        uint16_t        m_uid;
        enum PortType   m_type;
        unsigned int    m_ip;
        uint16_t        m_port;
        std::string     m_path; /* unix sockets */
      };

  typedef std::vector<CBound>    BoundList;
  typedef std::vector<CBound>::iterator  BoundListIterator;
      
  class CProcess
  {  
      friend class CProcInfo;
      public:
        CProcess() :
      m_gotBoundList(false)
      {}
      
    const unsigned int GetPID      () { return m_pid      ; }
    const std::string& GetExe      () { return m_exe      ; }
    const std::string& GetComm     () { return m_comm     ; }
    const std::string& GetCmdLine  () { return m_cmdLine  ; }
    const BoundList&   GetBoundList();
        
      private:
      
    std::string m_procPath;

    unsigned int m_pid;
    std::string  m_exe;
    std::string  m_comm;
    std::string  m_cmdLine;
    
    bool        m_gotBoundList;
    BoundList   m_boundList;
  };
  
  typedef std::vector<CProcess>           ProcessList;
  typedef std::vector<CProcess>::iterator ProcessListIterator;

  static void  ClearCache();
  static const ProcessList& GetProcessList();
  static const BoundList&   GetBoundList();  
      
    protected:
    private:
    static bool         m_gotProcessList;
    static ProcessList  m_processList;
    static bool         m_gotBindings;
    static BoundList    m_bindings;
};

#endif // _CPROCINFO_H_
