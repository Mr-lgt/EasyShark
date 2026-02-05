//
// Created by Mr.Lu on 2025/11/2.
//

#ifndef TSHARK_DATATYPE_H
#define TSHARK_DATATYPE_H

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <cstdint>  // 包含标准整数类型定义
#include <string>   // 包含std::string定义

struct PcapHeader {
  uint32_t magic_number;    // 文件格式标识符
  uint16_t version_major;   // 主版本号
  uint16_t version_minor;   // 次版本号
  int32_t thiszone;         // 时区偏移
  uint32_t sigfigs;         // 时间戳精度
  uint32_t snaplen;         // 最大捕获长度
  uint32_t network;         // 链路层类型
};

// 数据包包头结构
struct PacketHeader {
  uint32_t ts_sec;         // 时间戳（秒）
  uint32_t ts_usec;        // 时间戳（微秒）
  uint32_t caplen;         // 捕获的数据长度
  uint32_t len;            // 原始数据长度
};

struct Packet {
  int frame_number;            // 数据包编号
  double time;            // 数据包的时间戳
  std::string src_mac;
  std::string dst_mac;
  uint32_t cap_len;
  uint32_t len;
  std::string src_ip;            // 源IP地址
  uint16_t src_port;            //源端口号
  std::string src_location;       //源IP归属地
  std::string dst_ip;            // 目的IP地址
  uint16_t dst_port;            //目的端口号
  std::string dst_location;     //目的IP归属地
  std::string protocol;        // 协议
  std::string info;            // 数据包的概要信息
  uint32_t file_offset;
};

// 网卡信息
struct AdapterInfo {
  int id;
  std::string name;
  std::string remark;
};

#endif // TSHARK_DATATYPE_H

