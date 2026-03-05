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

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

class BaseDataObject {
public:
    // 将对象转换为JSON Value，用于转换为JSON格式输出
    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const = 0;
};

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

class Packet{
public:
    int frame_number;
    double time;
    uint32_t cap_len;
    uint32_t len;
    std::string src_mac;
    std::string dst_mac;
    std::string src_ip;
    std::string src_location;
    uint16_t src_port;
    std::string dst_ip;
    std::string dst_location;
    uint16_t dst_port;
    std::string protocol;
    std::string info;
    uint32_t file_offset;

    void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        rapidjson::Value pktObj(rapidjson::kObjectType);
        obj.AddMember("frame_number", frame_number, allocator);
        obj.AddMember("timestamp", time, allocator);
        obj.AddMember("src_mac", rapidjson::Value(src_mac.c_str(), allocator), allocator);
        obj.AddMember("dst_mac", rapidjson::Value(dst_mac.c_str(), allocator), allocator);
        obj.AddMember("src_ip", rapidjson::Value(src_ip.c_str(), allocator), allocator);
        obj.AddMember("src_location", rapidjson::Value(src_location.c_str(), allocator), allocator);
        obj.AddMember("src_port", src_port, allocator);
        obj.AddMember("dst_ip", rapidjson::Value(dst_ip.c_str(), allocator), allocator);
        obj.AddMember("dst_location", rapidjson::Value(dst_location.c_str(), allocator), allocator);
        obj.AddMember("dst_port", dst_port, allocator);
        obj.AddMember("len", len, allocator);
        obj.AddMember("cap_len", cap_len, allocator);
        obj.AddMember("protocol", rapidjson::Value(protocol.c_str(), allocator), allocator);
        obj.AddMember("info", rapidjson::Value(info.c_str(), allocator), allocator);
        obj.AddMember("file_offset", file_offset, allocator);
    }
};

// 网卡信息
struct AdapterInfo {
  int id;
  std::string name;
  std::string remark;
};

// 查询条件
class QueryCondition {
public:
    std::string ip;
    uint16_t port = 0;
    std::string proto;
};

#endif // TSHARK_DATATYPE_H

