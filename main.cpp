// EasyTshark.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
#include "task/TsharkManager.h"

void InitLog(int argc, char *argv[])
{
    // 初始化 Loguru
    loguru::init(argc, argv);

    // 设置日志文件路径
    loguru::add_file("app.log", loguru::Append, loguru::Verbosity_MAX);
}

void translationDemo(TsharkManager &tsharkManager, const std::string &workDir)
{
    // 1. 提示用户输入PCAP文件路径
    std::string pcapFilePath;
    LOG_F(INFO, "请输入要分析的PCAP文件路径: ");
    std::getline(std::cin, pcapFilePath);

    // 2. 分析数据包
    if (tsharkManager.analysisFile(pcapFilePath))
    {
        // 3. 获取数据包总数
        size_t totalPackets = tsharkManager.getAllPacketsCount();
        LOG_F(INFO, "分析完成，共捕获到 %d 个数据包", totalPackets);

        // 4. 提示用户输入要获取详情的数据包编号
        int packetIndex;
        LOG_F(INFO, "请输入要获取详情的数据包编号: ");
        std::cin >> packetIndex;

        // 5. 验证输入的数据包编号是否有效
        if (packetIndex >= 1 && packetIndex <= totalPackets)
        {
            std::string packetDetail;
            if (tsharkManager.getPacketDetailInfo(packetIndex, packetDetail))
            {
                // 6. 保存数据包详情到本地文件
                std::string outputFilePath = workDir + std::to_string(packetIndex) + ".json";
                std::ofstream outputFile(outputFilePath);
                if (outputFile.is_open())
                {
                    outputFile << packetDetail;
                    outputFile.close();
                    LOG_F(INFO, "数据包详情已保存到 %s", outputFilePath.c_str());
                }
                else
                {
                    LOG_F(ERROR, "无法打开文件 %s 进行写入", outputFilePath.c_str());
                }
            }
        }
        else
        {
            LOG_F(ERROR, "无效的数据包编号 %d", packetIndex);
        }
    }
    else
    {
        LOG_F(ERROR, "分析文件 %s 失败", pcapFilePath.c_str());
    }
}

void jsonDemo(TsharkManager &tsharkManager)
{
    tsharkManager.startMonitorAdaptersFlowTrend();

    std::this_thread::sleep_for(std::chrono::seconds(10));

    std::map<std::string, std::map<long, long>> trendData;
    tsharkManager.getAdaptersFlowTrendData(trendData);

    tsharkManager.stopMonitorAdaptersFlowTrend();

    // 把获取到的数据打印输出
    rapidjson::Document resDoc;
    rapidjson::Document::AllocatorType &allocator = resDoc.GetAllocator();
    resDoc.SetObject();
    rapidjson::Value dataObject(rapidjson::kObjectType);
    for (const auto &adaptorItem : trendData)
    {
        rapidjson::Value adaptorDataList(rapidjson::kArrayType);
        for (const auto &timeItem : adaptorItem.second)
        {
            rapidjson::Value timeObj(rapidjson::kObjectType);
            timeObj.AddMember("time", (unsigned int)timeItem.first, allocator);
            timeObj.AddMember("bytes", (unsigned int)timeItem.second, allocator);
            adaptorDataList.PushBack(timeObj, allocator);
        }
        dataObject.AddMember(rapidjson::StringRef(adaptorItem.first.c_str()), adaptorDataList, allocator);
    }

    resDoc.AddMember("data", dataObject, allocator);

    // 序列化为 JSON 字符串
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    resDoc.Accept(writer);

    LOG_F(INFO, "网卡流量监控数据: %s", buffer.GetString());
}

int main(int argc, char *argv[])
{
    // 设置控制台环境编码为UTF-8格式，防止打印输出的内容乱码
    setlocale(LC_ALL, "zh_CN.UTF-8");

    InitLog(argc, argv);

    std::string workDir = "E:/MyProject/EasyTshark/";
    TsharkManager tsharkManager(workDir);

    tsharkManager.startCapture("WLAN");

    std::string input;
    while (true)
    {
        std::cout << "请输入q退出抓包\n";
        std::cin >> input;
        if (input == "q")
        {
            tsharkManager.stopCapture();
            break;
        }
    }
    // tsharkManager.printAllPackets();
    // tsharkManager.analysisFile("E:/pcap/packets2.pcap");

    //    std::vector<AdapterInfo> adaptors = tsharkManager.getNetworkAdapters();
    //    for (const auto& item : adaptors) {
    //        LOG_F(INFO, "网卡[%d]: name[%s] remark[%s]", item.id, item.name.c_str(), item.remark.c_str());
    //    }
    //
    //
    //    std::cout << "按回车键退出" << std::endl;
    //    std::cin.get();

    return 0;
}
