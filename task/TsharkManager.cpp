//
// Created by Mr.Lu on 2025/11/2.
//
#include "TsharkManager.h"

TsharkManager::TsharkManager(std::string workDir)
{
    this->tsharkPath = "D:/wireshark/tshark";
    this->editcapPath = "D:/wireshark/editcap";
    // 解析IP归属地
    std::string xdbPath = workDir + "third_library/ip2region/ip2region.xdb";
    IP2RegionUtil::init(xdbPath);
    
    // 初始化数据库连接
    std::string dbPath = workDir + "tshark_data2.db";
    storage = std::make_shared<TsharkDataBase>(dbPath);
}

TsharkManager::~TsharkManager()
{
    IP2RegionUtil::uninit();
}

bool TsharkManager::analysisFile(std::string filePath)
{
    std::vector<std::string> tsharkArgs = {
        tsharkPath,
        "-r", filePath,
        "-T", "fields"};
    auto commonFields = getCommonTsharkFields;
    tsharkArgs.insert(tsharkArgs.end(), commonFields.begin(), commonFields.end());

    std::string command = buildCommand(tsharkArgs);

    LOG_F(INFO, "解析文件数据......");
    FILE *pipe = popen(command.c_str(), "r");
    if (!pipe)
    {
        LOG_F(ERROR, "Failed to run tshark command!");
        return false;
    }

    char buffer[4096];
    // 当前处理的报文在文件中的偏移，第一个报文的偏移就是全局文件头24(也就是sizeof(PcapHeader))字节
    uint32_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {

        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!parseLine(buffer, packet))
        {
            LOG_F(ERROR, "failed to analysis packet %s", buffer);
            assert(false); // 增加错误断言，及时发现错误
        }

        // 计算当前报文的偏移，然后记录在Packet对象中
        packet->file_offset = file_offset + sizeof(PacketHeader);

        // 更新偏移游标
        file_offset = file_offset + sizeof(PacketHeader) + packet->cap_len;

        // 获取IP地理位置
        packet->src_location = IP2RegionUtil::getIpLocation(packet->src_ip);
        packet->dst_location = IP2RegionUtil::getIpLocation(packet->dst_ip);

        // 将分析的数据包插入保存起来
        allPackets.insert(std::make_pair<>(packet->frame_number, packet));
    }

    pclose(pipe);

    // 记录当前分析的文件路径
    currentFilePath = filePath;

    LOG_F(INFO, "分析完成，数据包总数：%zu", allPackets.size());
    return true;
}

std::string TsharkManager::buildCommand(const std::vector<std::string> &tsharkArgs)
{
    std::string command;
    for (const auto &arg : tsharkArgs)
    {
        command += arg;
        command += " ";
    }
    return command;
}

void TsharkManager::printAllPackets()
{
    for (const auto &pair : allPackets)
    {
        std::shared_ptr<Packet> packet = pair.second;

        // 构建JSON对象
        rapidjson::Document pktObj;
        rapidjson::Document::AllocatorType &allocator = pktObj.GetAllocator();
        pktObj.SetObject();

        pktObj.AddMember("frame_number", packet->frame_number, allocator);
        pktObj.AddMember("timestamp", packet->time, allocator);
        pktObj.AddMember("src_mac", rapidjson::Value(packet->src_mac.c_str(), allocator), allocator);
        pktObj.AddMember("dst_mac", rapidjson::Value(packet->dst_mac.c_str(), allocator), allocator);
        pktObj.AddMember("src_ip", rapidjson::Value(packet->src_ip.c_str(), allocator), allocator);
        pktObj.AddMember("src_location", rapidjson::Value(packet->src_location.c_str(), allocator), allocator);
        pktObj.AddMember("src_port", packet->src_port, allocator);
        pktObj.AddMember("dst_ip", rapidjson::Value(packet->dst_ip.c_str(), allocator), allocator);
        pktObj.AddMember("dst_location", rapidjson::Value(packet->dst_location.c_str(), allocator), allocator);
        pktObj.AddMember("dst_port", packet->dst_port, allocator);
        pktObj.AddMember("protocol", rapidjson::Value(packet->protocol.c_str(), allocator), allocator);
        pktObj.AddMember("info", rapidjson::Value(packet->info.c_str(), allocator), allocator);
        pktObj.AddMember("file_offset", packet->file_offset, allocator);
        pktObj.AddMember("cap_len", packet->cap_len, allocator);
        pktObj.AddMember("len", packet->len, allocator);

        // 序列化为 JSON 字符串
        rapidjson::StringBuffer buffer;
        rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
        writer.SetIndent(' ', 2);
        pktObj.Accept(writer);

        // 打印JSON输出
        LOG_F(INFO, "Print packet: %s", buffer.GetString());
    }
}

bool TsharkManager::getPacketHexData(uint32_t frameNumber, std::vector<unsigned char> &data)
{
    // 打开文件（二进制模式）
    std::ifstream file(currentFilePath, std::ios::binary);
    if (!file.is_open())
    {
        LOG_F(ERROR, "Failed to open file %s", currentFilePath.c_str());
        return false;
    }

    std::shared_ptr<Packet> packet = allPackets[frameNumber];

    // 定位到指定偏移量
    file.seekg(packet->file_offset, std::ios::beg);
    if (!file)
    {
        LOG_F(ERROR, "Failed to set offset of file: %u", packet->file_offset);
        file.close();
        return false;
    }

    // 调整缓冲区大小
    data.resize(packet->cap_len);
    // 读取数据包内容
    file.read(reinterpret_cast<char *>(data.data()), packet->cap_len);
    // 检查读取是否成功
    if (!file || file.gcount() != static_cast<std::streamsize>(packet->cap_len))
    {
        LOG_F(ERROR, "Error! Fail to read packet. original length: %d"
                     ", current file length: %d",
              packet->cap_len, (int)file.gcount());
        file.close();
        return false;
    }

    file.close();
    return true;
}

bool TsharkManager::parseLine(std::string line, std::shared_ptr<Packet> packet)
{
    if (line.back() == '\n')
    {
        line.pop_back();
    }
    std::stringstream ss(line);
    std::string field;
    std::vector<std::string> fields;

    // 自己实现字符串拆分
    size_t start = 0, end;
    while ((end = line.find('\t', start)) != std::string::npos)
    {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start)); // 添加最后一个子串

    // 字段顺序：
    // 0: frame.number
    // 1: frame.time_epoch
    // 2: frame.len
    // 3: frame.cap_len
    // 4: eth.src
    // 5: eth.dst
    // 6: ip.src
    // 7: ipv6.src
    // 8: ip.dst
    // 9: ipv6.dst
    // 10: tcp.srcport
    // 11: udp.srcport
    // 12: tcp.dstport
    // 13: udp.dstport
    // 14: _ws.col.Protocol
    // 15: _ws.col.Info

    if (fields.size() >= 16)
    {
        packet->frame_number = std::stoi(fields[0]);
        packet->time = std::stod(fields[1]);
        packet->len = std::stoi(fields[2]);
        packet->cap_len = std::stoi(fields[3]);
        packet->src_mac = fields[4];
        packet->dst_mac = fields[5];
        packet->src_ip = fields[6].empty() ? fields[7] : fields[6];
        packet->dst_ip = fields[8].empty() ? fields[9] : fields[8];
        if (!fields[10].empty() || !fields[11].empty())
        {
            packet->src_port = std::stoi(fields[10].empty() ? fields[11] : fields[10]);
        }

        if (!fields[12].empty() || !fields[13].empty())
        {
            packet->dst_port = std::stoi(fields[12].empty() ? fields[13] : fields[12]);
        }
        packet->protocol = fields[14];
        packet->info = fields[15];

        return true;
    }
    else
    {
        return false;
    }
}

std::vector<AdapterInfo> TsharkManager::getNetworkAdapters()
{

    // 需要过滤掉的虚拟网卡，这些不是真实的网卡。tshark -D命令可能会输出这些，把它过滤掉
    std::set<std::string> specialInterfaces = {"sshdump", "ciscodump", "udpdump", "randpkt", "etwdump"};
    // 枚举到的网卡列表
    std::vector<AdapterInfo> interfaces;

    char buffer[256] = {0};
    std::string result;
    // 启动tshark -D命令
    std::string cmd = tsharkPath + " -D";

    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe)
    {
        throw std::runtime_error("Failed to run tshark command.");
    }

    while (fgets(buffer, 36, pipe) != nullptr)
    {
        result += buffer;
    }

    std::istringstream stream(result);
    std::string line;
    int index = 1;
    while (std::getline(stream, line))
    {
        int startPos = line.find(' ');
        if (startPos != std::string::npos)
        {
            int endPos = line.find(' ', startPos + 1);
            std::string interfaceName;

            if (endPos != std::string::npos)
            {
                interfaceName = line.substr(startPos + 1, endPos - (startPos + 1));
            }
            else
            {
                interfaceName = line.substr(startPos + 1);
            }

            // 滤掉特殊网卡
            if (specialInterfaces.find(interfaceName) != specialInterfaces.end())
            {
                continue;
            }

            AdapterInfo adapterInfo;
            adapterInfo.name = interfaceName;
            adapterInfo.id = index++;

            // 定位到括号，把括号里面的备注内容提取出来
            if (line.find('(') != std::string::npos && line.find(')') != std::string::npos)
            {
                adapterInfo.remark = line.substr(line.find('(') + 1, line.find(')') - 1);
            }
            interfaces.push_back(adapterInfo);
        }
    }

    pclose(pipe);
    return interfaces;
}

bool TsharkManager::startCapture(std::string adapterName)
{
    LOG_F(INFO, "即将开始抓包，网卡：%s", adapterName.c_str());
    // 关闭停止标记
    stopFlag = false;
    storageThread =
        std::make_shared<std::thread>(&TsharkManager::storageThreadEntry, this);
    captureWorkThread =
        std::make_shared<std::thread>(&TsharkManager::captureWorkThreadEntry, this, "\"" + adapterName + "\"");
    return true;
}

bool TsharkManager::stopCapture()
{
    LOG_F(INFO, "即将停止抓包");
    stopFlag = true;
    // 主动终止tshark进程，而不是等待管道自然关闭
    LOG_F(INFO, "正在终止tshark进程...");
    ProcessUtil::Kill(captureTsharkPid);
    captureWorkThread->join();
    captureWorkThread.reset();
    // 等待存储线程结束
    storageThread->join();
    storageThread.reset();

    LOG_F(INFO, "抓包已完全停止");
    return true;
}

void TsharkManager::captureWorkThreadEntry(const std::string &adapterName)
{
    std::string captureFile = "capture.pcap";

    std::vector<std::string> tsharkArgs = {
        tsharkPath,
        "-i",
        adapterName,
        "-w",
        captureFile, // 默认将采集到的数据包写入到这个文件下
        "-F",
        "pcap", // 指定存储的格式为PCAP格式
        "-T",
        "fields",
    };
    auto commonFields = getCommonTsharkFields;
    tsharkArgs.insert(tsharkArgs.end(), commonFields.begin(), commonFields.end());

    std::string command = buildCommand(tsharkArgs);
    FILE *pipe = ProcessUtil::PopenEx(command, &captureTsharkPid);
    if (!pipe)
    {
        LOG_F(ERROR, "Failed to run tshark command!");
        return;
    }

    char buffer[4096];
    // 当前处理的报文在文件中的偏移，第一个报文的偏移就是全局文件头24(也就是sizeof(PcapHeader))字节
    uint32_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr && !stopFlag)
    {

        std::string line = buffer;
        if (line.find("Capturing on") != std::string::npos)
        {
            continue;
        }

        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!parseLine(line, packet))
        {
            LOG_F(ERROR, "failed to analysis packet %s", buffer);
            assert(false);
        }

        // 计算当前报文的偏移，然后记录在Packet对象中
        packet->file_offset = file_offset + sizeof(PacketHeader);
        // 更新偏移游标
        file_offset = file_offset + sizeof(PacketHeader) + packet->cap_len;
        // 获取IP地理位置
        packet->src_location = IP2RegionUtil::getIpLocation(packet->src_ip);
        packet->dst_location = IP2RegionUtil::getIpLocation(packet->dst_ip);

        processPackets(packet);
    }

    pclose(pipe);
    // 记录当前分析的文件路径
    currentFilePath = captureFile;
}

void TsharkManager::startMonitorAdaptersFlowTrend()
{
    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);
    adapterFlowTrendMonitorStartTime = time(nullptr);

    // 第一步：获取网卡列表
    std::vector<AdapterInfo> adapterList = getNetworkAdapters();

    // 第二步：每个网卡启动一个线程，统计对应网卡的数据
    for (const auto &adapter : adapterList)
    {
        adapterFlowTrendMonitorMap.insert(std::make_pair<>(adapter.name, AdapterMonitorInfo()));
        AdapterMonitorInfo &monitorInfo = adapterFlowTrendMonitorMap.at(adapter.name);

        monitorInfo.monitorThread =
            std::make_shared<std::thread>(&TsharkManager::adapterFlowTrendMonitorThreadEntry, this, adapter.name);
        if (monitorInfo.monitorThread == nullptr)
        {
            LOG_F(ERROR, "监控线程创建失败，网卡名：%s", adapter.name.c_str());
        }
        else
        {
            LOG_F(INFO, "监控线程创建成功，网卡名：%s，monitorThread: %p", adapter.name.c_str(), monitorInfo.monitorThread.get());
        }
    }
}

void TsharkManager::adapterFlowTrendMonitorThreadEntry(const std::string &adapterName)
{
    if (adapterFlowTrendMonitorMap.find(adapterName) == adapterFlowTrendMonitorMap.end())
    {
        return;
    }

    std::map<long, long> &trafficPerSecond = adapterFlowTrendMonitorMap[adapterName].flowTrendData;
    char buffer[256] = {0};

    // Tshark命令，指定网卡，实时捕获时间戳和数据包长度
    std::vector<std::string> tsharkArgs = {
        tsharkPath,
        "-i",
        adapterName,
        "-T",
        "fields",
    };
    std::vector<std::string> params = {
        "-e",
        "frame.time_epoch",
        "-e",
        "frame.len",
    };
    tsharkArgs.insert(tsharkArgs.end(), params.begin(), params.end());
    std::string tsharkCmd = buildCommand(tsharkArgs);
    //    std::string tsharkCmd = tsharkPath + " -i \"" + adapterName + "\" -T fields -e frame.time_epoch -e frame.len";

    LOG_F(INFO, "启动网卡流量监控: %s", tsharkCmd.c_str());

    PID_T tsharkPid = 0;
    FILE *pipe = ProcessUtil::PopenEx(tsharkCmd, &tsharkPid);
    if (!pipe)
    {
        throw std::runtime_error("Failed to run tshark command.");
    }

    // 将管道保存起来
    adapterFlowTrendMapLock.lock();
    adapterFlowTrendMonitorMap[adapterName].monitorTsharkPipe = pipe;
    adapterFlowTrendMonitorMap[adapterName].tsharkPid = tsharkPid;
    adapterFlowTrendMapLock.unlock();

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        std::string line(buffer);
        std::istringstream iss(line);
        std::string timestampStr, lengthStr;

        if (line.find("Capturing") != std::string::npos || line.find("captured") != std::string::npos)
        {
            continue;
        }

        // 解析每行的时间戳和数据包长度
        if (!(iss >> timestampStr >> lengthStr))
        {
            continue;
        }

        try
        {
            // 转换时间戳为long类型，秒数部分
            long timestamp = static_cast<long>(std::stod(timestampStr));
            // 转换数据包长度为long类型
            long packetLength = std::stol(lengthStr);
            // 每秒的字节数累加
            trafficPerSecond[timestamp] += packetLength;

            // 如果trafficPerSecond超过300秒，则删除最早的数据，始终只存储最近300秒的数据
            while (trafficPerSecond.size() > 300)
            {
                // 访问并删除最早的时间戳数据
                auto it = trafficPerSecond.begin();
                LOG_F(INFO, "Removing old data for second: %ld, Traffic: %ld bytes", it->first, it->second);
                trafficPerSecond.erase(it);
            }
        }
        catch (const std::exception &e)
        {
            // 处理转换错误
            LOG_F(ERROR, "Error parsing tshark output: %s", line.c_str());
        }
    }

    LOG_F(INFO, "adapterFlowTrendMonitorThreadEntry 已结束");
}

void TsharkManager::storageThreadEntry()
{
    auto storageWork = [this]()
    {
        storeLock.lock();
        // 检查数据包列表是否有新的数据可供存储
        if (!packetsTobeStore.empty())
        {
            storage->storePackets(packetsTobeStore);
            packetsTobeStore.clear();
        }
        storeLock.unlock();
    };
    // 只要停止标记没有点亮，存储线程就要一直存在
    while (!stopFlag)
    {
        storageWork();
        std::this_thread::sleep_for(std::chrono::seconds(100));
    }
    // 稍等一下最后再执行一次，防止有遗漏的数据未入库
    std::this_thread::sleep_for(std::chrono::seconds(1));
    storageWork();
}

void TsharkManager::stopMonitorAdaptersFlowTrend()
{
    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);

    for (const auto &adapterPipePair : adapterFlowTrendMonitorMap)
    {
        ProcessUtil::Kill(adapterPipePair.second.tsharkPid);
    }

    for (const auto &adapterPipePair : adapterFlowTrendMonitorMap)
    {
        // 然后关闭管道
        pclose(adapterPipePair.second.monitorTsharkPipe);
        // 最后等待对应线程退出
        adapterPipePair.second.monitorThread->join();
        LOG_F(INFO, "网卡：%s 流量监控已停止", adapterPipePair.first.c_str());
    }

    // 清空记录的流量趋势数据
    adapterFlowTrendMonitorMap.clear();
}

void TsharkManager::getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>> &flowTrendData)
{
    long timeNow = time(nullptr);

    // 数据从最左边冒出来
    // 一开始：以最开始监控时间为左起点，终点为未来300秒
    // 随着时间推移，数据逐渐填充完这300秒
    // 超过300秒之后，结束节点就是当前，开始节点就是当前-300
    // 数据从最左边冒出来
    // 一开始：以最开始监控时间为左起点，终点为未来300秒
    // 随着时间推移，数据逐渐填充完这300秒
    // 超过300秒之后，结束节点就是当前，开始节点就是当前-300
    long timeDiff = timeNow - adapterFlowTrendMonitorStartTime;
    long startWindow =
        timeDiff > 300 ? timeNow - 300 : adapterFlowTrendMonitorStartTime;
    long endWindow = timeDiff > 300 ? timeNow : adapterFlowTrendMonitorStartTime + 300;

    adapterFlowTrendMapLock.lock();
    for (auto adapterPipePair : adapterFlowTrendMonitorMap)
    {
        flowTrendData.insert(std::make_pair<>(adapterPipePair.first, std::map<long, long>()));

        // 从当前时间戳向前倒推300秒，构造map
        for (long t = startWindow; t <= endWindow; t++)
        {
            // 如果trafficPerSecond中存在该时间戳，则使用已有数据；否则填充为0
            if (adapterPipePair.second.flowTrendData.find(t) != adapterPipePair.second.flowTrendData.end())
            {
                flowTrendData[adapterPipePair.first][t] = adapterPipePair.second.flowTrendData.at(t);
            }
            else
            {
                flowTrendData[adapterPipePair.first][t] = 0;
            }
        }
    }
    adapterFlowTrendMapLock.unlock();
}

bool TsharkManager::getPacketDetailInfo(uint32_t frameNumber, std::string &result)
{
    std::string tmpFilePath = MiscUtil::getRandomString(10) + ".pcap";
    std::string splitCmd = editcapPath + " -r " + currentFilePath + " " + tmpFilePath + " " + std::to_string(frameNumber) + "-" + std::to_string(frameNumber);

    if (!ProcessUtil::Exec(splitCmd))
    {
        LOG_F(ERROR, "Error in executing command: %s", splitCmd.c_str());
        remove(tmpFilePath.c_str());
        return false;
    }

    // 通过tshark获取指定数据包详细信息，输出格式为XML
    // 启动'tshark -r ${tmpFilePath} -T pdml'命令，获取指定数据包的详情
    std::string cmd = tsharkPath + " -r " + tmpFilePath + " -T pdml";
    std::unique_ptr<FILE, decltype(&pclose)> pipe(ProcessUtil::PopenEx(cmd.c_str()), pclose);
    if (!pipe)
    {
        std::cout << "Failed to run tshark command." << std::endl;
        remove(tmpFilePath.c_str());
        return false;
    }

    // 读取tshark输出
    char buffer[8192] = {0};
    int count = 0;
    std::string tsharkResult;
    setvbuf(pipe.get(), NULL, _IOFBF, sizeof(buffer));
    while (fgets(buffer, sizeof(buffer) - 1, pipe.get()) != nullptr)
    {
        tsharkResult += buffer;
        memset(buffer, 0, sizeof(buffer));
    }

    remove(tmpFilePath.c_str());

    // 将xml内容转换为JSON
    Document detailJson;
    if (!MiscUtil::xml2JSON(tsharkResult, detailJson))
    {
        LOG_F(ERROR, "XML转JSON失败");
        return false;
    }

    // 翻译显示名称字段
    // 安全地逐层访问JSON成员，避免使用链式operator[]导致断言错误
    auto pdmlIt = detailJson.FindMember("pdml");
    if (pdmlIt != detailJson.MemberEnd() && pdmlIt->value.IsObject())
    {
        auto packetIt = pdmlIt->value.FindMember("packet");
        if (packetIt != pdmlIt->value.MemberEnd() && packetIt->value.IsArray() && packetIt->value.Size() > 0)
        {
            auto firstPacket = &packetIt->value[0]; // 数组元素访问是安全的
            if (firstPacket->IsObject())
            {
                // 1. 处理proto数组中的字段（这里包含需要翻译的showname字段）
                auto protoIt = firstPacket->FindMember("proto");
                if (protoIt != firstPacket->MemberEnd() && protoIt->value.IsArray())
                {
                    TranslatorUtil::translateShowNameFields(protoIt->value, detailJson.GetAllocator());
                }

                // 2. 处理packet直接包含的field字段（如果有的话）
                auto fieldIt = firstPacket->FindMember("field");
                if (fieldIt != firstPacket->MemberEnd())
                {
                    TranslatorUtil::translateShowNameFields(fieldIt->value, detailJson.GetAllocator());
                }
            }
        }
    }

    StringBuffer stringBuffer;
    PrettyWriter<StringBuffer> writer(stringBuffer);
    writer.SetIndent(' ', 2); // 设置缩进字符为空格，缩进2个空格
    detailJson.Accept(writer);

    // 设置数据包详情结果
    result = stringBuffer.GetString();

    return true;
}

size_t TsharkManager::getAllPacketsCount()
{
    return allPackets.size();
}

void TsharkManager::processPackets(std::shared_ptr<Packet> packet)
{
    // 将分析出来的数据包存起来
    allPackets.insert(std::make_pair<>(packet->frame_number, packet));

    //等待入库
    storeLock.lock();
    packetsTobeStore.push_back(packet);
    storeLock.unlock();
}
