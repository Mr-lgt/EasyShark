#pragma once

#include "base_controller.hpp"
#include "../task/TsharkManager.h"
#include <memory>

class PacketController : public BaseController {
public:
    PacketController(httplib::Server& server, std::shared_ptr<TsharkManager> tsharkManager)
        : BaseController(server, tsharkManager) {
    }

    virtual void registerRoute() {
        __server.Post("/packets", [this](const httplib::Request& req, httplib::Response& res) {
            getPacketList(req, res);
        });
    }

    // 获取数据包列表
    void getPacketList(const httplib::Request& req, httplib::Response& res) {
        // 获取 JSON 数据中的字段
        try
        {
            QueryCondition queryCondition;
            if (!parseQueryConditions(req, queryCondition)) {
                sendErrorResponse(res, ERROR_PARAMETER_WRONG);
                return;
            }

            // 调用 tSharkManager 的方法获取数据
            std::vector<std::shared_ptr<Packet>> packetList;
            __tsharkManager->queryPackets(queryCondition, packetList);
            sendDataList(res, packetList);
        }
        catch(const std::exception& e)
        {
            sendErrorResponse(res, ERROR_PARAMETER_WRONG);
        }
    }
};
