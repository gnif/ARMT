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

#ifndef _CSCHEDULER_H_
#define _CSCHEDULER_H_

#include <ctime>
#include <vector>

class ISchedulerJob
{
  public:
    ISchedulerJob() {}
    virtual ~ISchedulerJob() {}

    virtual std::time_t GetRunTime()  = 0;
    virtual void SetRunTime(std::time_t time) = 0;
    virtual unsigned int GetDelayInterval() = 0;
    virtual void Execute() = 0;
};

class CScheduler
{
  public:
    CScheduler();
    ~CScheduler();

    /**
     * Run's any jobs that need running
     * @return True if any jobs ran
     */
    bool Run();

    /**
     * Add a recurring job to execute at the specified time
     * @param job An instance of ISchedulerJob
     */
    void AddJob(ISchedulerJob *job);

  private:
    typedef std::vector<ISchedulerJob *> JobList;

    JobList m_jobs;
};

#endif // _CSCHEDULER_H_
