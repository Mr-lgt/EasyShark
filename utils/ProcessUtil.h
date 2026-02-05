//
// Created by Mr.Lu on 2025/11/19.
//

#ifndef EASYTSHARK_UTILS_PROCESSUTIL_H_
#define EASYTSHARK_UTILS_PROCESSUTIL_H_

#ifdef _WIN32
#include <windows.h>
typedef DWORD PID_T;
#else
#include <unistd.h>
#include <sys/types.h>
typedef pid_t PID_T;
#endif

#include <iostream>
#include <fcntl.h>

/**
 * 处理进程的工具类
 */
class ProcessUtil {

 public:
  //打开管道
  static FILE* PopenEx(std::string command, PID_T* pidOut = nullptr);

  //杀死进程
  static int Kill(PID_T pid);

  //启动进程
  static bool Exec(std::string cmdline);

};

#endif //EASYTSHARK_UTILS_PROCESSUTIL_H_
