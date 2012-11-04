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

#include "CCommon.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <assert.h>

#include <stdarg.h>
#include <sys/wait.h>
#include <sstream>
#include <string>

#include <algorithm>
#include <functional>
#include <cctype>
#include <locale>

#include "CDNS.h"

#include "../utils/cciss_vol_status.h"
#include "../utils/smartctl.h"
#include "../utils/lsscsi.h"
#include "../utils/megactl.h"

/* static declarations */
bool             CCommon::m_isBE;
std::string      CCommon::m_exePath;
std::string      CCommon::m_basePath;
entropy_context  CCommon::m_entropy;
ctr_drbg_context CCommon::m_drbg;

bool __attribute__((optimize("O0"))) detectBE()
{
  union { uint32_t i; char c[4];} bint = {0x01020304};
  return bint.c[0] == 1;
}

void CCommon::Initialize(const int argc, char* const argv[])
{
  /* see if we are a BE cpu */
  m_isBE = detectBE();

  /* get the application's base directory */
  char *exePath  = realpath(argv[0], NULL);
  char *basePath = dirname(exePath);

  m_exePath  = exePath;
  m_basePath = basePath;
  free(exePath);

  /* change our cwd to our base path */
  chdir(m_basePath.c_str());

  /* ensure the bin dir exists */
  if (!IsDir("bin"))
    mkdir("bin", 0700);

  /* unpack the support binaries */
  WriteExe("bin/cciss_vol_status", cciss_vol_status, cciss_vol_status_size);
  WriteExe("bin/smartctl"        , smartctl        , smartctl_size        );
  WriteExe("bin/lsscsi"          , lsscsi          , lsscsi_size          );
  WriteExe("bin/megactl"         , megactl         , megactl_size         );
  WriteExe("bin/megasasctl"      , megasasctl      , megasasctl_size      );

  /* init entropy for SSL/RSA */
  const char *pers = "ARMT_CHTTPS";
  entropy_init(&m_entropy);
  assert(ctr_drbg_init(&m_drbg, entropy_func, &m_entropy, (unsigned char* )pers, strlen(pers)) == 0);
}


void CCommon::Trim(std::string &s)
{
  s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
}

std::string CCommon::IntToStr(int value, int base/* = 10*/)
{
  std::string buf;
  if (base < 2 || base > 16)
    return buf;

  buf.reserve(35);
  int quotient = value;

  do
  {
    buf += "0123456789abcdef"[std::abs(quotient % base)];
    quotient /= base;
  }
  while (quotient);

  if (value < 0)
    buf += '-';

  std::reverse(buf.begin(), buf.end());
  return buf;
}

std::string CCommon::StrToLower(std::string string)
{
  std::transform(string.begin(), string.end(), string.begin(), ::tolower);
  return string;
}

bool CCommon::IsFile(const std::string &path)
{
  struct stat st;
  if (stat(path.c_str(), &st) != 0)
    return false;

  return S_ISREG(st.st_mode);
}

bool CCommon::IsDir(const std::string &path)
{
  struct stat st;
  if (stat(path.c_str(), &st) != 0)
    return false;

  return S_ISDIR(st.st_mode);
}

bool CCommon::WriteBuffer(const std::string &path, const void *buffer, const size_t size)
{
  if (FILE *fd = fopen(path.c_str(), "w"))
  {
    if (fwrite(buffer, 1, size, fd) == size)
    {
      fclose(fd);
      return true;
    }

    fclose(fd);
    return false;
  }

  return false;
}

bool CCommon::WriteExe(const std::string &path, const void *buffer, const size_t size)
{
  /* ensure the buffer is large enough for the memcmp */
  if (size < 4)
    return false;

  /* ensure we are writing an ELF */
  if (memcmp(buffer, "\x7f" "ELF", 4) != 0)
    return false;

  /* write the file */
  if (!WriteBuffer(path, buffer, size))
    return false;

  /* make it executable */
  if (chmod(path.c_str(), 0700) < 0)
    return false;

  return true;
}

/* read a file containing a single boolean flag */
bool CCommon::SimpleReadBool(const std::string &path, bool &dest)
{
  dest = false;
  if (FILE *fd = fopen(path.c_str(), "r"))
  {
    char buffer[1];

    if (fread(buffer, 1, 1, fd) == 1)
    {
      fclose(fd);
      dest = (buffer[0] == '1');
      return true;
    }

    fclose(fd);
  }

  return false;
}

bool CCommon::SimpleReadStr(const std::string &path, std::string &dest)
{
  dest.erase();
  if (FILE *fd = fopen(path.c_str(), "r"))
   {
    char buffer[128];
    size_t len = fread(buffer, 1, sizeof(buffer), fd);
    if (len > 0)
    {
      fclose(fd);

      while(
        buffer[len-1] == '\0' ||
        buffer[len-1] == '\r' ||
        buffer[len-1] == '\n' ||
        buffer[len-1] == ' '
      ) --len;

      dest.assign(buffer, len);
      return true;
    }

    fclose(fd);
  }

  return false;
}

/* read a file containing a single int32_t */
bool CCommon::SimpleReadInt32(const std::string &path, int32_t &dest, const int base)
{
  long value;
  dest = 0;
  if (FILE *fd = fopen(path.c_str(), "r"))
   {
    char buffer[128];
    int length;
    if ((length = fread(buffer, 1, sizeof(buffer)-1, fd)) > 0)
    {
      fclose(fd);

      /* make sure the buffer is null terminated and parse it */
      buffer[length] = '\0';
      value = strtol(buffer, NULL, base);
      if (value > INT32_MAX || value < INT32_MIN)
        return false;

      dest = value;
      return true;
    }

    fclose(fd);
  }

  return false;
}

/* read a file containing a single int16_t */
bool CCommon::SimpleReadInt16(const std::string &path, int16_t &dest, const int base)
{
  dest = 0;
  int32_t value;
  if (!SimpleReadInt32(path, value, base))
    return false;

  if (value > INT16_MAX || value < INT16_MIN)
    return false;

  dest = value;
  return true;
}

/* read a file containing a single uint32_t */
bool CCommon::SimpleReadUInt32(const std::string &path, uint32_t &dest, const int base)
{
  unsigned long value;
  dest = 0;
  if (FILE *fd = fopen(path.c_str(), "r"))
   {
    char buffer[128];
    int length;
    if ((length = fread(buffer, 1, sizeof(buffer)-1, fd)) > 0)
    {
      fclose(fd);

      /* make sure the buffer is null terminated and parse it */
      buffer[length] = '\0';
      value = strtoul(buffer, NULL, base);
      if (value > UINT32_MAX)
        return false;

      dest = value;
      return true;
    }

    fclose(fd);
  }

  return false;
}

/* read a file containing a single uint16_t */
bool CCommon::SimpleReadUInt16(const std::string &path, uint16_t &dest, const int base)
{
  dest = 0;
  uint32_t value;
  if (!SimpleReadUInt32(path, value, base))
    return false;

  if (value > UINT16_MAX)
    return false;

  dest = value;
  return true;
}

bool CCommon::RunCommand(std::string &result, const std::string &cmd, ...)
{
  /* create a pipe for IPC */
  int pipefd[2];
  pipe(pipefd);

  pid_t pid = fork();
  switch(pid)
  {
    /* failure */
    case -1:
      return false;

    /* child */
    case 0: {
      /* redirect stdin/out to the pipe */
      close(pipefd[0]);
      dup2(pipefd[1], 1);
      dup2(pipefd[1], 2);
      close(pipefd[1]);

      /* count the arguments */
      int argc = 0;
      va_list vl;
      va_start(vl, cmd);
      while(va_arg(vl, char *) != NULL)
        ++argc;
      va_end(vl);

      /* allocate the argument array and initialize it */
      char *argv[argc+2];
      argv[0] = (char *)malloc(cmd.length() + 1); 
      strcpy(argv[0], cmd.c_str());
      argv[argc+1] = NULL;

      /* set the arguments */
      va_start(vl, cmd);
      for(int i = 1; char *arg = va_arg(vl, char*); ++i)
        argv[i] = arg;
      va_end(vl);

      /* execute the command */
      execve(argv[0], argv, NULL);
      exit(1); /* should never get here */
    }

    /* parent */
    default: {
      close(pipefd[1]);
      char buffer[8192];
      ssize_t length;

      result.erase();
      while((length = read(pipefd[0], buffer, sizeof(buffer))) > 0)
        result.append(buffer, length);

      int status;
      while(waitpid(pid, &status, 0) > -1)
      {
        if (WIFEXITED(status) || WIFSIGNALED(status))
          break;
      }

      close(pipefd[0]);
      return true;
    }
  }
}
