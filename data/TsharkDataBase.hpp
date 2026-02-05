#include "sqlite3/sqlite3.h"
#include "tshark_datatype.h"
#include "../utils/misc_util.hpp"
#include "loguru/loguru.hpp"

class TsharkDataBase
{
private:
    sqlite3 *db = nullptr; // SQLite 数据库连接

private:
    bool createPacketTable()
    {
        // 检查表是否存在，若不存在则创建
        std::string createTableSQL = R"(
        CREATE TABLE IF NOT EXISTS t_packets (
            frame_number INTEGER PRIMARY KEY,
            time REAL,
            cap_len INTEGER,
            len INTEGER,
            src_mac TEXT,
            dst_mac TEXT,
            src_ip TEXT,
            src_location TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_location TEXT,
            dst_port INTEGER,
            protocol TEXT,
            info TEXT,
            file_offset INTEGER
        );
    )";

        int rc = sqlite3_exec(db, createTableSQL.c_str(), nullptr, nullptr, nullptr);
        if (rc != SQLITE_OK)
        {
            LOG_F(ERROR, "创建数据包表失败: %s", sqlite3_errmsg(db));
            return false;
        }

        return true;
    }

public:
    TsharkDataBase(const std::string &dbName)
    {
        int rc = sqlite3_open(dbName.c_str(), &db);
        if (rc != SQLITE_OK)
        {
            LOG_F(ERROR, "无法打开数据库 %s: %s", dbName.c_str(), sqlite3_errmsg(db));
            db = nullptr;
        }
        createPacketTable(); // 在构造函数中调用
    }

    ~TsharkDataBase()
    {
        if (db != nullptr)
        {
            sqlite3_close(db);
            db = nullptr;
        }
    }

    bool storePackets(std::vector<std::shared_ptr<Packet>> &packets)
    {
        // 开启事务
        sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

        // 准备插入语句
        const char *insertSQL = R"(
            INSERT INTO t_packets (
                frame_number, time, cap_len, len,
                src_mac, dst_mac,
                src_ip, src_location, src_port,
                dst_ip, dst_location, dst_port,
                protocol, info, file_offset
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        )";

        sqlite3_stmt *stmt = nullptr;
        int rc = sqlite3_prepare_v2(db, insertSQL, -1, &stmt, nullptr);
        if (rc != SQLITE_OK)
        {
            throw std::runtime_error("Failed to prepare insert statement");
        }

        // 遍历列表并插入数据
        bool hasError = false;
        for (const auto &pkt : packets)
        {
            sqlite3_bind_int(stmt, 1, pkt->frame_number);
            sqlite3_bind_double(stmt, 2, pkt->time);
            sqlite3_bind_int(stmt, 3, pkt->cap_len);
            sqlite3_bind_int(stmt, 4, pkt->len);
            sqlite3_bind_text(stmt, 5, pkt->src_mac.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 6, pkt->dst_mac.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 7, pkt->src_ip.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 8, pkt->src_location.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 9, pkt->src_port);
            sqlite3_bind_text(stmt, 10, pkt->dst_ip.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 11, pkt->dst_location.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 12, pkt->dst_port);
            sqlite3_bind_text(stmt, 13, pkt->protocol.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 14, pkt->info.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 15, pkt->file_offset);

            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE)
            {
                LOG_F(ERROR, "Failed to execute insert statement");
                hasError = true;
                break;
            }

            sqlite3_reset(stmt); // 重置语句以便下一次绑定
        }

        if (!hasError)
        {
            // 结束事务
            if (sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr) != SQLITE_OK)
            {
                hasError = true;
            }
            // 释放语句
            sqlite3_finalize(stmt);
        }

        return !hasError;
    }

    bool queryPackets(std::vector<std::shared_ptr<Packet>> &packetList)
    {
        // 从数据库查询数据包分页数据
        sqlite3_stmt *stmt = nullptr;
        std::string sql = "select * from t_packets";
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        {
            LOG_F(ERROR, "Failed to prepare statement: %s", sqlite3_errmsg(db));
            return false;
        }

        // 执行查询语句
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            std::shared_ptr<Packet> pkt = std::make_shared<Packet>();
            pkt->frame_number = sqlite3_column_int(stmt, 0);
            pkt->time = sqlite3_column_double(stmt, 1);
            pkt->cap_len = sqlite3_column_int(stmt, 2);
            pkt->len = sqlite3_column_int(stmt, 3);
            pkt->src_mac = (const char *)sqlite3_column_text(stmt, 4);
            pkt->dst_mac = (const char *)sqlite3_column_text(stmt, 5);
            pkt->src_ip = (const char *)sqlite3_column_text(stmt, 6);
            pkt->src_location = (const char *)sqlite3_column_text(stmt, 7);
            pkt->src_port = sqlite3_column_int(stmt, 8);
            pkt->dst_ip = (const char *)sqlite3_column_text(stmt, 9);

            pkt->dst_location = (const char *)sqlite3_column_text(stmt, 10);
            pkt->dst_port = sqlite3_column_int(stmt, 11);
            pkt->protocol = (const char *)sqlite3_column_text(stmt, 12);
            pkt->info = (const char *)sqlite3_column_text(stmt, 13);
            pkt->file_offset = sqlite3_column_int64(stmt, 14);

            packetList.push_back(pkt);
        }

        // 释放语句
        sqlite3_finalize(stmt);

        return true;
    }
};

