#include "utils/misc_util.hpp"
#include <iostream>

int main1() {
    // 测试XML内容，包含节点文本
    std::string xmlContent = R"(
<root>
    <person id="1">
        <name>John Doe</name>
        <age>30</age>
        <email>john@example.com</email>
        <bio>Software developer with 5 years of experience</bio>
    </person>
    <person id="2">
        <name>Jane Smith</name>
        <age>25</age>
        <email>jane@example.com</email>
        <bio>Data scientist specializing in machine learning</bio>
    </person>
    <note hide="true">This note should be hidden</note>
</root>
    )";

    // 转换为JSON
    rapidjson::Document jsonDoc;
    bool result = MiscUtil::xml2JSON(xmlContent, jsonDoc);

    if (result) {
        // 打印JSON结果
        rapidjson::StringBuffer buffer;
        rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
        jsonDoc.Accept(writer);
        std::cout << "JSON转换结果:\n" << buffer.GetString() << std::endl;
    } else {
        std::cerr << "XML转换失败" << std::endl;
        return 1;
    }

    return 0;
}