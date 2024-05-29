#include <string>
#include <iostream>
#include <sstream>
#include <functional>

#include "web.h"

static const char *s_json_header =
        "Content-Type: application/json\r\n"
        "Cache-Control: no-cache\r\n";

static void ev_handler(struct mg_connection *c, int ev, void *ev_data) {
    auto *self = (WebPage *) c->fn_data;

    if (ev == MG_EV_HTTP_MSG) {
        auto *hm = (struct mg_http_message *) ev_data;
        if (mg_match(hm->uri, mg_str("/pppwn.log"), nullptr)) {
            mg_printf(c, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n");
            self->addClient(c);
            mg_printf(c, "%s\n", self->getLog().c_str());
        } else if (mg_match(hm->uri, mg_str("/run"), nullptr)) {
            self->getLog().clear();
            std::cout << "[*] Starting..." << std::endl;
            self->startExploit();
            mg_http_reply(c, 200, s_json_header, "{\"code\": 200}");
        } else if (mg_match(hm->uri, mg_str("/stop"), nullptr)) {
            std::cout << "[*] Stopping..." << std::endl;
            self->stopExploit();
            mg_http_reply(c, 200, s_json_header, "{\"code\": 200}");
        } else {
            struct mg_http_serve_opts opts = {.root_dir= "/web", .fs = &mg_fs_packed};
            mg_http_serve_dir(c, hm, &opts);
        }
    } else if (ev == MG_EV_CLOSE) {
        self->removeClient(c);
    }
}

WebPage::WebPage(std::shared_ptr<Exploit> exploit) : exploit(std::move(exploit)) {
    buf.setCallback([this](const std::string &str) {
        this->broadcast(str);
    });
    stdbuf = std::cout.rdbuf(&buf);
}

WebPage::~WebPage() {
    std::cout.rdbuf(stdbuf);
}

void WebPage::setUrl(const std::string &url) {
    this->url = "http://" + url;
}

void WebPage::run() {
    mg_log_set(MG_LL_ERROR);
    struct mg_mgr mgr{};
    mg_mgr_init(&mgr);

    if (mg_http_listen(&mgr, url.c_str(), ev_handler, this) == nullptr) {
        printf("[-] Cannot listen on %s\n", url.c_str());
        return;
    } else {
        printf("[+] Starting web server on %s\n", url.c_str());
    }
    running = true;
    while (running) {
        mg_mgr_poll(&mgr, 50);
    }
    mg_mgr_free(&mgr);
    this->stopExploit();
}

void WebPage::stop() {
    running = false;
}

void WebPage::addClient(struct mg_connection *c) {
    std::lock_guard<std::mutex> lock(mutex);
    clients.insert(c);
}

void WebPage::removeClient(struct mg_connection *c) {
    std::lock_guard<std::mutex> lock(mutex);
    if (clients.find(c) != clients.end()) {
        clients.erase(c);
    }
}

void WebPage::broadcast(const std::string &msg) {
    if (msg.empty()) return;
    historyLog += "data: " + msg + "\n";
    if (msg[msg.length() - 1] != '\n') historyLog += "\n";
    std::lock_guard<std::mutex> lock(mutex);
    for (auto &client: clients) {
        mg_printf(client, "data: %s\n\n", msg.c_str());
    }
}

std::string &WebPage::getLog() {
    return historyLog;
}

void WebPage::startExploit() {
    exploit->stop();
    if (exploitThread.joinable())
        exploitThread.join();
    exploit->setWaitAfterPin(1);
    exploitThread = std::thread([this]() {
        return exploit->run();
    });
}

void WebPage::stopExploit() {
    exploit->stop();

    if (exploitThread.joinable())
        exploitThread.join();
    else
        std::cout << "[+] Already stopped" << std::endl;
}

void CustomBuf::setCallback(std::function<void(const std::string &)> cb) {
    this->callback = std::move(cb);
}

int CustomBuf::sync() {
    if (!oss.str().empty()) {
        if (callback) callback(oss.str());
        oss.str("");
    }
    return 0;
}

std::streambuf::int_type CustomBuf::overflow(int_type ch) {
    if (ch != traits_type::eof()) {
        if (ch != '\r')
            oss.put(ch);
    }
    return ch;
}