# 关于TLV(Type-Length-Value)格式的消息
TLV消息是一种由类型，长度，内容组成的消息。由于其结构简单通用，而且方便嵌套和扩展，特别适用于定义通信消息。  
为方便用户实现自定义协议，我们内置了TLV消息的支持。  

# TLV消息的结构
TLV消息并没有具体规定Type和Length这两个字段占的字节数据。在我们的协议里，它们分别占4字节（网络序）。  
也就是说，我们的消息有8字节的消息头，以及不超过32GB的Value内容。Type和Value域的含义我们不做规定。  

# TLVMessage类
由于TLV的定义内容很少，所以[TLVMessage](/src/protocol/TLVMessage.h)需要用到的接口很少。
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
用户直接使用TLV消息来做数据传输的话，只需要用到上面的几个接口。分别为设置和获取Type与Value。  
Value直接以std::string返回，方便用户必要的时候直接通过std::move移动数据。  

# 基于TLV消息的echo server/client
以下代码，直接启动一个基于TLV消息的server，并通过命令行产生client task进行交互。建议运行一下：
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

WFTLVTask *create_tlv_task(const char *host, unsigned short port,
						   tlv_callback_t callback)
{
	auto *task = WFNetworkTaskFactory<TLVRequest, TLVResponse>::create_client_task(
							TT_TCP, host, port, 0, std::move(callback));
	task->set_keep_alive(60 * 1000);
	return task;
}

int main()
{
	WFTLVServer server([](WFTLVTask *task){
		*task->get_resp() = std::move(*task->get_req());
	});

	if (server.start(8888) != 0)
	{
		perror("server.start");
		exit(1);
	}

	auto&& create = [](WFRepeaterTask *)->SubTask *{
		std::string string;
		printf("Input string (Ctrl-D to exit): ");
		std::cin >> string;
		if (string.empty())
		{
			printf("\n");
			return NULL;
		}

		auto *task = create_tlv_task("127.0.0.1", 8888, [](WFTLVTask *task) {
			if (task->get_state() == WFT_STATE_SUCCESS)
				printf("Server Response: %s\n", task->get_resp()->get_value()->c_str());
			else
			{
				const char *str = WFGlobal::get_error_string(task->get_state(), task->get_error());
				fprintf(stderr, "Error: %s\n", str);
			}
		});

		task->get_req()->set_value(std::move(string));
		return task;
	};

	WFFacilities::WaitGroup wait_group(1);

	WFRepeaterTask *repeater;
	repeater = WFTaskFactory::create_repeater_task(std::move(create), nullptr);
	Workflow::start_series_work(repeater, [&wait_group](const SeriesWork *) {
		wait_group.done();
	});

	wait_group.wait();
	server.stop();
	return 0;
}

~~~

# 派生TLVMessage
上面的echo server实例，我们直接使用了原始的TLVMessage。但建议在具体的应用中，用户可以对消息进行派生。  
在派生类里，提供更加丰富的接口来设置和提取消息内容，避免直接操作原始Value域，并形成自己的二级协议。  
例如，我们实现一个JSON的协议，可以：
~~~cpp
#include "workflow/json-parser.h"    // 内置的json解析器

class JsonMessage : public TLVMessage
{
public:
    void set_json_value(const json_value_t *val)
    {
		this->type = JSON_TYPE;
        this->json_to_string(val, &this->value);  // 需要实现一下
    }

    json_value_t *get_json_value() const
    {
		if (this->type == JSON_TYPE)
            return json_parser_parse(this->value.c_str());  // json-parser的函数
        else
            return NULL;
    }
};

using JsonRequest = JsonMessage;
using JsonResponse = JsonMessage;

using JsonServer = WFServer<JsonRequest, JsonResponse>;
~~~
这个例子只是为了说明派生的重要性，实际应用中，派生类可能要远远比这个复杂。  
