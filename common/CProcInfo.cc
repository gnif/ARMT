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

#include "CProcInfo.h"
#include <dirent.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <string.h>
#include <netinet/in.h>
#include <limits.h>

/* static defines */
bool                   CProcInfo::m_gotProcessList = false;
CProcInfo::ProcessList CProcInfo::m_processList;
bool                   CProcInfo::m_gotBindings = false;
CProcInfo::BoundList   CProcInfo::m_bindings;

void CProcInfo::ClearCache()
{
  m_gotProcessList = false;
  m_processList.empty();
  m_gotBindings = false;
  m_bindings.empty();
}

const CProcInfo::ProcessList& CProcInfo::GetProcessList()
{
  if (m_gotProcessList)
    return m_processList;
  m_gotProcessList = true;

  DIR *dh = opendir("/proc");
  
  if (dh == NULL)
    return m_processList;

  while(struct dirent *dir = readdir(dh))
  {
    bool invalid = false;
    
    /* filter out non-numeric paths */ 
    for(unsigned int i = 0; dir->d_name[i] != '\0'; ++i)
      if (dir->d_name[i] < '0' || dir->d_name[i] > '9')
      {
        invalid = true;
        break;
      }
    
    if (invalid) continue;
    
    /* build the path to the files */
    std::string path = "/proc/";
    path.append(dir->d_name);
    
    /* check the exe "file" exists */
    struct stat sb;
    if (stat((path + "/exe").c_str(), &sb) != 0 || !(S_ISREG(sb.st_mode) || S_ISLNK(sb.st_mode)))
      continue;
    
    CProcess proc;
    proc.m_procPath = path;
    proc.m_pid      = atoi(dir->d_name);
    
    /* get the exe name */
    char buffer[1024];
    ssize_t length = readlink((path + "/exe").c_str(), buffer, sizeof(buffer)-1);

    if (length > 0)
      proc.m_exe.append(buffer, length);

    /* get the comm name */
    FILE *fd = fopen((path + "/comm").c_str(), "r");
    if (fd)
    {
      fgets(buffer, sizeof(buffer)-1, fd);
      for(unsigned int i = strlen(buffer)-1; buffer[i] == '\n'; --i)
        buffer[i] = '\0';
        
      proc.m_comm.append(buffer);
      fclose(fd);      
    }

    /* get the command line */
    fd = fopen((path + "/cmdline").c_str(), "r");
    if (fd)
    {
      fgets(buffer, sizeof(buffer)-1, fd);
      proc.m_cmdLine.append(buffer);
      fclose(fd);
    }
    
    /* add the process to the list */    
    m_processList.push_back(proc);
  }
  
  closedir(dh);
  return m_processList;
}

const CProcInfo::BoundList& CProcInfo::GetBoundList()
{
  if (m_gotBindings)
    return m_bindings;
  m_gotBindings = true;
  
  for(
    int portTypeInt = PORT_TYPE_TCP;
    portTypeInt != PORT_TYPE_COUNT;
    ++portTypeInt
  ) {
    enum PortType portType = static_cast<PortType>(portTypeInt);
    const char* path;
    
    switch(portType)
    {
      case PORT_TYPE_TCP : path = "/proc/net/tcp" ; break;
      case PORT_TYPE_UDP : path = "/proc/net/udp" ; break;
      case PORT_TYPE_UNIX: path = "/proc/net/unix"; break;
      
      default:
        continue;
    }

    char buffer[1024];
    FILE *fd = fopen(path, "r");
    if (!fd)
      continue;
  
    bool first = true;
    while(fgets(buffer, sizeof(buffer)-1, fd) != NULL)
    {
      /* skip the first line, it contains the headings */
      if (first)
      {
        first = false;
        continue;
      }
        
      /* remove alignment padding from the output so sscanf can work */
      std::string line;
      for(char *ptr = buffer; *ptr != '\0'; ++ptr)
      {
        if (*ptr == '\n' || (ptr != buffer && (*(ptr - 1) == ' ' && *ptr == ' ')))
          continue;
        
        line += *ptr;
      }

      if (portType == PORT_TYPE_TCP || portType == PORT_TYPE_UDP)
      {
        unsigned int localAddress;
        unsigned int localPort;
        unsigned int remoteAddress;
        unsigned int status;
        unsigned int uid;
        unsigned int inode;
    
        if (sscanf(buffer,
          " %*u: %8x:%4x %8x:%*4x %2x %*8x:%*8x %*2x:%*8x %*8x %u %*u %u",
          &localAddress,
          &localPort,
          &remoteAddress,
          &status,
          &uid,
          &inode
        ) != 6)
          continue;
    
        /* we dont care about connected ports, we only want bindings */
        if (remoteAddress != 0 || !(status & 0xA))
          continue;
    
        CBound bound;
        bound.m_socket = inode;
        bound.m_uid    = uid;
        bound.m_type   = portType;
        bound.m_ip     = ntohl(localAddress);
        bound.m_port   = localPort;
        m_bindings.push_back(bound);
        continue;
      }
      
      if (portType == PORT_TYPE_UNIX) {
        unsigned int state;
        unsigned int inode;
        char         path[PATH_MAX];
        
        if (sscanf(buffer,
          " %*x: %*8x %*8x %*8x %*4x %2x %u %s",
          &state,
          &inode,
          path
        ) != 3)
          continue;
        
        /* only listening sockets */
        if (state != 0x1) continue;
        
        CBound bound;
        bound.m_socket = inode;
        bound.m_type   = portType;
        bound.m_path   = path; 
        m_bindings.push_back(bound);
        continue;        
      }
    }
  
    fclose(fd);
  }
  
  return m_bindings;
}

const CProcInfo::BoundList& CProcInfo::CProcess::GetBoundList()
{
  if (m_gotBoundList)
    return m_boundList;
  m_gotBoundList = true;

  DIR* dh = opendir((m_procPath + "/fd").c_str());
  if (dh == NULL)
    return m_boundList;
    
  BoundList fullList = CProcInfo::GetBoundList();
  
  while(struct dirent *dir = readdir(dh))
  {
    if (dir->d_name[0] == '.') continue;
    
    std::string path = m_procPath + "/fd/";
    path.append(dir->d_name);
    
  /* get the link name */
  char buffer[1024];
  ssize_t length = readlink(path.c_str(), buffer, sizeof(buffer)-1);
  buffer[length] = '\0';
      
  /* parse out the socket fd */
  unsigned int socket;
  if (sscanf(buffer, "socket:[%u]", &socket) != 1)
    continue;
  
  for(BoundListIterator itt = fullList.begin(); itt != fullList.end(); ++itt)
    if (itt->m_socket == socket)
    {
      m_boundList.push_back(*itt);
      break;
    }
  }

  closedir(dh);  
  return m_boundList;
}
