# About TLV (Type-Length-Value) format message
A TLV message is a message consisting of type, length, and value. Because its format is simple and universal, and it is convenient for nesting and expansion, it is especially suitable for defining communication messages. To facilitate users to implement custom protocols, we have built-in support for TLV messages.
# TLV message structure
The general TLV structure does not specify the bytes of the Type or Length field. In our protocol, they occupy 4 bytes each (network order). In other words, our message has an 8-byte message header and a Value content of no more than 32GB. We do not specify the meaning of the Type and Value fields.
# TLVMessage class
Because the definition of TLV format is simple. The interfaces of this TLVMessage are very simple too.
~~~cpp
namespace protocol
{
class TLVMessage : public ProtocolMessage
{
public:
    int get_type() const { return this->type; }
    void set_type(int type) { this->type = type; }

    std::string *get_value() { return &this->value; }
    void set_value(std::string value) { this->value = std::move(value); }

protected:
    int type;
    std::string value;

    ...
};

using TLVRequest = TLVMessage;
using TLVResposne = TLVMessage;
}
~~~
If users directly use TLV messages for data transmission, they only need to use the above interfaces. Set and get Type and Value respectively. Value is directly returned as ``std::string``, which is convenient for users to move data directly through ``std::move`` when necessary.
# An echo server/client example based on TLV message
The following code directly starts a server based on TLV messages, and generates a client task through the command line for interaction.
~~~cpp
#include <stdio.h>
#include <string>
#include <iostream>
#include "workflow/WFGlobal.h"
#include "workflow/WFFacilities.h"
#include "workflow/TLVMessage.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/WFServer.h"

using namespace protocol;

using WFTLVServer = WFServer<TLVRequest, TLVResponse>;
using WFTLVTask = WFNetworkTask<TLVRequest, TLVResponse>;
using tlv_callback_t = std::function<void (WFTLVTask *)>;

WFTLVTask *create_tlv_task(const char *host, unsigned short port, tlv_callback_t callback)
{
    auto *task = WFNetworkTaskFactory<TLVRequest, TLVResponse>::create_client_task(
                                       TT_TCP, host, port, 0, std::move(callback));
    task->set_keep_alive(60 * 1000);
    return task;
}

int main()
{
    WFTLVServer server([](WFTLVTask *task) {
        *task->get_resp() = std::move(*task->get_req());
    });

    if (server.start(8888) != 0) {
        perror("server.start");
        exit(1);
    }

    auto&& create = [](WFRepeaterTask *)->SubTask * {
        std::string string;
        printf("Input string (Ctrl-D to exit): ");
        std::cin >> string;
        if (string.empty())
            return NULL;

        auto *task = create_tlv_task("127.0.0.1", 8888, [](WFTLVTask *task) {
            if (task->get_state() == WFT_STATE_SUCCESS)
                printf("Server Response: %s\n", task->get_resp()->get_value()->c_str());
            else {
                const char *str = WFGlobal::get_error_string(task->get_state(), task->get_error());
                fprintf(stderr, "Error: %s\n", str);
            }
        });

        task->get_req()->set_value(std::move(string));
        return task;
    };

    WFFacilities::WaitGroup wait_group(1);
    WFRepeaterTask *repeater = WFTaskFactory::create_repeater_task(std::move(create), nullptr);
    Workflow::start_series_work(repeater, [&wait_group](const SeriesWork *) {
        wait_group.done();
    });

    wait_group.wait();
    server.stop();
    return 0;
}
~~~
# To extend TLVMessage
In the echo server example above, we directly use the original TLVMessage. However, it is suggested that in specific applications, users can derive TLVMessage. In the derived class, provide a richer interface to set and extract message content, avoid direct manipulation of the original Value field, and form its own secondary protocol.
For example, if we implement a JSON protocol, we can:
~~~cpp
#include "workflow/json-parser.h"    // built-in JSON parser

class JsonMessage : public TLVMessage
{
public:
    void set_json_value(const json_value_t *val)
    {
        this->type = JSON_TYPE;
        this->json_to_string(val, &this->value);  // you have to implement this function
    }

    json_value_t *get_json_value() const
    {
        if (this->type == JSON_TYPE)
            return json_parser_parse(this->value.c_str());  // json-parser's interface
        else
            return NULL;
    }
};

using JsonRequest = JsonMessage;
using JsonResponse = JsonMessage;

using JsonServer = WFServer<JsonRequest, JsonResponse>;
~~~
This example is just to illustrate the importance of derivation. In actual applications, derived classes may be far more complicated than this.
