//
// Created by Mr.Lu on 2025/11/2.
//
#pragma once

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "../utils/ip2region_util.h"
#include "../data/tshark_datatype.h"
#include "loguru/loguru.hpp"
#include "../utils/ProcessUtil.h"
#include "../utils/misc_util.hpp"
#include "../utils/translator_util.hpp"
#include "../data/TsharkDataBase.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <set>
#include <thread>
#include <map>
#include <mutex>

#if _WIN32
#define popen _popen
#define pclose _pclose
#endif

class TsharkManager
{
public:
  TsharkManager(std::string workDir);
  ~TsharkManager();

  // 分析数据包文件
  bool analysisFile(std::string filePath);

  // 打印所有数据包的信息
  void printAllPackets();

  // 获取指定编号数据包的十六进制数据
  bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char> &data);

  // 枚举网卡列表
  std::vector<AdapterInfo> getNetworkAdapters();

  // 开始抓包
  bool startCapture(std::string adapterName);

  // 停止抓包
  bool stopCapture();

  // 开始监控所有网卡流量统计数据
  void startMonitorAdaptersFlowTrend();

  // 停止监控所有网卡流量统计数据
  void stopMonitorAdaptersFlowTrend();

  // 获取所有网卡流量统计数据
  // 函数的参数是一个map，key是网卡名，value就是这个网卡的监控数据，这又是一个map。
  // 这个内层map的key就是时间戳（long型变量），value就是这一秒时间戳的流量统计字节数
  void getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>> &flowTrendData);

  // 获取指定数据包的详细信息
  bool getPacketDetailInfo(uint32_t frameNumber, std::string &result);

  // 获取数据包总数
  size_t getAllPacketsCount();

  // 处理解析出的数据包
  void processPackets(std::shared_ptr<Packet> packet);

  // -----------------------------数据查询相关接口-----------------------------------
  void queryPackets(QueryCondition &queryCondition, std::vector<std::shared_ptr<Packet>> &packets);

private:
  // 解析每一行
  bool parseLine(std::string line, std::shared_ptr<Packet> packet);

  // 在线采集数据包的工作线程
  void captureWorkThreadEntry(const std::string &adapterName);

  // 获取tshark命令
  static std::string buildCommand(const std::vector<std::string> &tsharkArgs);

  // 获取指定网卡的流量趋势数据
  void adapterFlowTrendMonitorThreadEntry(const std::string &adapterName);

  // 负责存储数据包和会话信息的存储线程函数
  void storageThreadEntry();

private:
  std::string tsharkPath;

  // 当前分析的文件路径
  std::string currentFilePath;

  // 用于编辑当前数据包的路径
  std::string editcapPath;

  // 分析得到的所有数据包信息，key是数据包ID，value是数据包信息指针，方便根据编号获取指定数据包信息
  std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;
  // 启用抓包的子线程
  std::shared_ptr<std::thread> captureWorkThread;

  // 是否停止抓包的标记
  bool stopFlag;

  // 在线抓包的tshark进程PID
  PID_T captureTsharkPid = 0;

  // 等待存储入库的数据
  std::vector<std::shared_ptr<Packet>> packetsTobeStore;

  // 访问待存储数据的锁
  std::mutex storeLock;

  // 存储线程，负责将获取到的数据包和会话信息存储入库
  std::shared_ptr<std::thread> storageThread;

  // 数据库存储
  std::shared_ptr<TsharkDataBase> storage;

  // 获取tshark命令参数
  std::vector<std::string> getCommonTsharkFields = {
      "-e",
      "frame.number",
      "-e",
      "frame.time_epoch",
      "-e",
      "frame.len",
      "-e",
      "frame.cap_len",
      "-e",
      "eth.src",
      "-e",
      "eth.dst",
      "-e",
      "ip.src",
      "-e",
      "ipv6.src",
      "-e",
      "ip.dst",
      "-e",
      "ipv6.dst",
      "-e",
      "tcp.srcport",
      "-e",
      "udp.srcport",
      "-e",
      "tcp.dstport",
      "-e",
      "udp.dstport",
      "-e",
      "_ws.col.Protocol",
      "-e",
      "_ws.col.Info",
  };

  // -----------------------------以下与网卡流量趋势监控有关-----------------------------------
  // 网卡监控相关的信息
  class AdapterMonitorInfo
  {
  public:
    AdapterMonitorInfo()
    {
      monitorTsharkPipe = nullptr;
      tsharkPid = 0;
    }
    std::string adapterName;                    // 网卡名称
    std::map<long, long> flowTrendData;         // 流量趋势数据
    std::shared_ptr<std::thread> monitorThread; // 负责监控该网卡输出的线程
    FILE *monitorTsharkPipe;                    // 线程与tshark通信的管道
    PID_T tsharkPid;                            // 负责捕获该网卡数据的tshark进程PID
  };

  // 后台流量趋势监控信息
  std::map<std::string, AdapterMonitorInfo> adapterFlowTrendMonitorMap;

  // 访问上面流量趋势数据的锁
  std::recursive_mutex adapterFlowTrendMapLock;

  // 网卡流量监控的开始时间
  long adapterFlowTrendMonitorStartTime = 0;
};