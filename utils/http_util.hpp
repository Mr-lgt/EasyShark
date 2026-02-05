#pragma once

#include <iostream>
#include "httplib/httplib.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

class HttpUtil
{
public:
    HttpUtil() = default;

    ~HttpUtil() = default;

    void queryPacket(const httplib::Request &req, httplib::Response &res)
    {
        // 解析传入的 JSON 数据
        rapidjson::Document doc;
        if (doc.Parse(req.body.c_str()).HasParseError())
        {
            res.status = 400;
            res.set_content("Invalid JSON format", "text/plain");
            return;
        }

        // 获取 JSON 数据中的字段
        do
        {
            std::string ip;
            uint16_t port;

            // 提取IP字段
            if (doc.HasMember("ip") && doc["ip"].IsString())
            {
                ip = doc["ip"].GetString();
            }
            else
            {
                res.status = 400;
                res.set_content("Missing 'ip' field in JSON", "text/plain");
                return;
            }

            // 提取端口字段
            if (doc.HasMember("port") && doc["port"].IsNumber())
            {
                port = doc["port"].GetUint();
            }
            else
            {
                res.status = 400;
                res.set_content("Missing 'port' field in JSON", "text/plain");
                return;
            }
            // 准备返回数据，构造一条假数据：
            rapidjson::Document res_doc;
            auto allocator = res_doc.GetAllocator();
            res_doc.SetObject();
            res_doc.AddMember("src_ip", ip, allocator);
            res_doc.AddMember("src_port", port, allocator);
            res_doc.AddMember("dst_ip", ip, allocator);
            res_doc.AddMember("dst_port", port, allocator);
            res_doc.AddMember("proto", "TCP", allocator);

            // 将 JSON 响应序列化为字符串
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            res_doc.Accept(writer);
            res.set_content(buffer.GetString(), "application/json");
        } while (false);
    }

    static httplib::Client createClient(const std::string &host, int port)
    {
        return httplib::Client(host, port);
    }

    static httplib::Result get(httplib::Client &client, const std::string &path)
    {
        return client.Get(path);
    }

    static httplib::Result post(httplib::Client &client, const std::string &path, const std::string &body,
                                const std::string &content_type = "application/json")
    {
        return client.Post(path, body, content_type.c_str());
    }

    static httplib::Result put(httplib::Client &client, const std::string &path, const std::string &body,
                               const std::string &content_type = "application/json")
    {
        return client.Put(path, body, content_type.c_str());
    }

    static httplib::Result del(httplib::Client &client, const std::string &path)
    {
        return client.Delete(path);
    }
};
