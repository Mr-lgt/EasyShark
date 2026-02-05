#ifndef MISC_UTIL_HPP
#define MISC_UTIL_HPP

// 通用头文件
#include <string>
#include <fstream>
#include <sstream>
#include <ctime>
#include <random>
#include <iostream>
#include <sys/stat.h>
#include <set>
#include <chrono>
#include <codecvt>
#include "rapidxml/rapidxml.hpp"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

// 操作系统特定头文件包含
#ifdef _WIN32
// Windows特定头文件
#include <windows.h>
#include <direct.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#define make_dir(path) _mkdir(path.c_str())
#define STAT_STRUCT _stat
#define STAT_FUNC _stat
#else
#include <unistd.h>
#include <iostream>

#define STAT_STRUCT stat
#define STAT_FUNC stat
#define make_dir(path) mkdir(path.c_str(), 0755)
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

using namespace rapidxml;
using namespace rapidjson;
/**
 * MiscUtil 工具类
 * 提供各种通用工具函数
 */
class MiscUtil
{
public:
    /**
     * 生成指定长度的随机字符串
     * @param length 字符串长度
     * @return 生成的随机字符串
     */
    static std::string getRandomString(size_t length)
    {
        // 定义包含26个字母大小写和0-9数字的字符集
        const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        // 创建随机设备用于生成种子
        std::random_device rd;

        // 创建Mersenne Twister生成器并设置种子
        std::mt19937 generator(rd());

        // 创建均匀分布，范围为字符集的索引
        std::uniform_int_distribution<> distribution(0, chars.size() - 1);

        // 生成随机字符串
        std::string result;

        for (size_t i = 0; i < length; ++i)
        {
            result += chars[distribution(generator)];
        }

        return result;
    }

    /**
     * 将XML内容转换为JSON文档
     * @param xmlContent XML内容字符串
     * @param outJsonDoc 输出的JSON文档
     * @return 转换成功返回true，失败返回false
     */
    static bool xml2JSON(std::string xmlContent, Document &outJsonDoc)
    {
        // 第一步：解析XML
        rapidxml::xml_document<> doc;
        try
        {
            doc.parse<0>(&xmlContent[0]);
        }
        catch (const rapidxml::parse_error &e)
        {
            std::cerr << "XML Parsing error: " << e.what() << std::endl;
            return false;
        }

        // 第二步：创建JSON文档
        outJsonDoc.SetObject();
        Document::AllocatorType &allocator = outJsonDoc.GetAllocator();

        // 第三步：获取XML根节点
        rapidxml::xml_node<> *root = doc.first_node();

        // 4.1：若根节点存在，将根节点转换为JSON
        if (root)
        {
            // 创建根节点对应的JSON对象
            rapidjson::Value rootJson(rapidjson::kObjectType);
            // 递归转换根节点
            xml_to_json_recursive(rootJson, root, allocator);

            // 4.2：将根节点添加到JSON文档
            outJsonDoc.AddMember(
                Value(root->name(), allocator).Move(),
                rootJson,
                allocator);
        }

        // 函数最后返回true
        return true;
    }

private:
    /**
     * 递归将XML节点转换为JSON对象
     * @param json JSON对象引用
     * @param node XML节点指针
     * @param allocator JSON分配器
     */
    static void xml_to_json_recursive(Value &json, xml_node<> *node, Document::AllocatorType &allocator)
    {
        for (xml_node<> *child = node->first_node(); child; child = child->next_sibling())
        {
            // 跳过文本节点（只处理元素节点）
            if (child->type() == rapidxml::node_data || child->type() == rapidxml::node_cdata)
            {
                continue;
            }
            
            // 检查是否需要跳过该节点（如果hide属性值为"true"）
            xml_attribute<> *hideAttr = child->first_attribute("hide");
            if (hideAttr && strcmp(hideAttr->value(), "true") == 0)
            {
                continue; // 跳过当前节点
            }

            // 检查是否已经有该节点名称的数组
            Value *array = nullptr;
            if (json.HasMember(child->name()))
            {
                array = &json[child->name()];
            }
            else
            {
                Value nodeArray(kArrayType);    // 创建新的数组
                json.AddMember(Value(child->name(), allocator).Move(), nodeArray, allocator);
                array = &json[child->name()];
            }

            // 创建一个 JSON 对象代表当前节点
            Value childJson(kObjectType);
            for (xml_attribute<> *attr = child->first_attribute(); attr; attr = attr->next_attribute())
            {
                Value arrayName = Value(attr->name(), allocator);
                Value arrayValue = Value(attr->value(), allocator);
                childJson.AddMember(arrayName,arrayValue,allocator);
            }
            
            // 处理节点文本内容
            if (child->value() && strlen(child->value()) > 0)
            {
                // 使用"content"字段存储节点文本内容
                Value contentKey = Value("content", allocator);
                Value contentValue = Value(child->value(), allocator);
                childJson.AddMember(contentKey, contentValue, allocator);
            }
            
            // 递归处理子节点
            xml_to_json_recursive(childJson, child, allocator);
            // 将子节点JSON添加到数组
            array->PushBack(childJson, allocator);
        }
    }

};

#endif // MISC_UTIL_HPP