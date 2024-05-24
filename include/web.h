#pragma once

#include <unordered_set>
#include <mutex>
#include <atomic>
#include <thread>
#include <utility>

#include <mongoose.h>

#include "exploit.h"

class CustomBuf : public std::streambuf {
public:
    void setCallback(std::function<void(const std::string &)> cb);

protected:
    int sync() override;

    int_type overflow(int_type ch) override;

private:
    std::ostringstream oss;
    std::function<void(const std::string &)> callback = nullptr;
};

class WebPage {
public:
    explicit WebPage(std::shared_ptr<Exploit> exploit);

    ~WebPage();

    void setUrl(const std::string &url);

    void run();

    void stop();

    void addClient(struct mg_connection *c);

    void removeClient(struct mg_connection *c);

    void broadcast(const std::string &msg);

    std::string &getLog();

    void startExploit();

    void stopExploit();

private:
    std::shared_ptr<Exploit> exploit;
    std::unordered_set<struct mg_connection *> clients;
    std::mutex mutex;
    std::thread exploitThread;
    std::atomic<bool> running{false};
    CustomBuf buf;
    std::streambuf *stdbuf;
    std::string historyLog;
    std::string url = "http://0.0.0.0:7796";
};
