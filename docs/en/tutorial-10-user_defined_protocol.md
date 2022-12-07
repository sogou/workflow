# A simple user-defined protocol: client/server 

# Sample codes

[message.h](/tutorial/tutorial-10-user_defined_protocol/message.h)  
[message.cc](/tutorial/tutorial-10-user_defined_protocol/message.cc)  
[server.cc](/tutorial/tutorial-10-user_defined_protocol/server.cc)  
[client.cc](/tutorial/tutorial-10-user_defined_protocol/client.cc)

# About user\_defined\_protocol

This example designs a simple communication protocol, and builds a server and a client on that protocol. The server converts the message sent by client into uppercase and returns it to the client.

# Protocol format

The protocol message contains one 4-byte head and one message body. Head is an integer in network byte order, indicating the length of body.   
The formats of the request messages and the response messages are identical.

# Protocol implementation

A user-defined protocol should provide its own serialization and deserialization methods, which are virtual functions in ProtocolMeessage class.   
In addition, for the convenience of use, we strongly recommend users to implement the **move constructor** and **move assignment** for messages (for std::move ()). [ProtocolMessage.h](/src/protocol/ProtocolMessage.h) contains the following serialization and deserialization interfaces:

~~~cpp
namespace protocol
{

class ProtocolMessage : public CommMessageOut, public CommMessageIn
{
private:
    virtual int encode(struct iovec vectors[], int max);

    /* You have to implement one of the 'append' functions, and the first one
     * with arguement 'size_t *size' is recommmended. */
    virtual int append(const void *buf, size_t *size);
    virtual int append(const void *buf, size_t size);

    ...
};

}
~~~

### Serialization function: encode

* The encode function is called before the message is sent, and it is called only once for each message.
* In the encode function, you need to serialize the message into a vector array, and the number of array elements must not exceed max. Current the value of max is 8192.
* For the definition of **struct iovec**, please see the system calls **readv** or **writev**.
* Normally the return value of the encode function is between 0 and max, indicating how many vector are used in the message.
  * In case of UDP protocol, please note that the total length must not be more than 64k, and no more than 1024 vectors are used (in Linux, writev writes only 1024 vectors at one time).
    * UDP protocol can only be used for a client, and UDP server cannot be realized.
* The encode -1 indicates errors. To return -1, you need to set errno. If the return value is > max, you will get an EOVERFLOW error. All errors are obtained in the callback.
* For performance reasons, the content pointed to by the iov\_base pointer in the vector will not be copied. So it generally points to the member of the message class.

### Deserialization function: append

* The append function is called every time a data block is received. Therefore, for each message, it may be called multiple times.
* buf and size are the content and the length of received data block respectively. You need to move the data content.
  * If the interface **append(const void \*buf, size\_t \*size)** is implemented, you can tell the framework how much length is consumed at this time by modifying \* size. remaining size = received size - consumed size, and the remaining part of the buf will be received again when the append is called next time. This function is more convenient for protocol parsing. Of course, you can also move the whole content and manage it by yourself. In this case, you do not need to modify \*size.
* If the **append** function returns 0, it indicates that the message is incomplete and the transmission continues. The return value of 1 indicates the end of the message. -1 indicates errors, and you need to set errno.
* In a word, the append function is used to tell the framework whether the message transmission is completed or not. Please don't perform complicated and unnecessary protocol parsing in the append.

### Setting the errno

* If encode or append returns -1 or other negative numbers, it should be interpreted as failure, and you should set the errno to pass the error reason. You can obtain this error in the callback.
* If the system calls or the library functions such as libc fail (for example, malloc), libc will definitely set errno, and you do not need to set it again.
* Some errors of illegal messages are quite common. For example, EBADMSG or EMSGSIZE can be used to indicate that the message content is wrong and the message is too large respectively.
* You can use a value that exceeds the errno range defined in the system to indicate a user-defined error. Generally, you can use a value greater than 256.
* Please do not use a negative errno. Because negative numbers are used inside the framework to indicate SSL errors.

In our example, the serialization and deserialization of messages are very simple.   
The header file [message.h](/tutorial/tutorial-10-user_defined_protocol/message.h) declares the request class and the response class.

~~~cpp
namespace protocol
{

class TutorialMessage : public ProtocolMessage
{
private:
    virtual int encode(struct iovec vectors[], int max);
    virtual int append(const void *buf, size_t size);
    ...
};

using TutorialRequest = TutorialMessage;
using TutorialResponse = TutorialMessage;

}
~~~

Both the request class and the response class belong to the same type of messages. You can directly introduce them with using.   
Note that both the request and the response can be constructed without parameters. In other words, you must provide a constructor without parameters or no constructor. In addition, the response object may be destroyed and reconstruct during communication if retrial occurs, therefore it should be a RAII class, otherwise things will be complicated).  
[message.cc](/tutorial/tutorial-10-user_defined_protocol/message.cc) contains the implementation of encode and append:

~~~cpp
namespace protocol
{

int TutorialMessage::encode(struct iovec vectors[], int max/*max==8192*/)
{
    uint32_t n = htonl(this->body_size);

    memcpy(this->head, &n, 4);
    vectors[0].iov_base = this->head;
    vectors[0].iov_len = 4;
    vectors[1].iov_base = this->body;
    vectors[1].iov_len = this->body_size;

    return 2;    /* return the number of vectors used, no more then max. */
}

int TutorialMessage::append(const void *buf, size_t size)
{
    if (this->head_received < 4)
    {
        size_t head_left;
        void *p;

        p = &this->head[this->head_received];
        head_left = 4 - this->head_received;
        if (size < 4 - this->head_received)
        {
            memcpy(p, buf, size);
            this->head_received += size;
            return 0;
        }

        memcpy(p, buf, head_left);
        size -= head_left;
        buf = (const char *)buf + head_left;

        p = this->head;
        this->body_size = ntohl(*(uint32_t *)p);
        if (this->body_size > this->size_limit)
        {
            errno = EMSGSIZE;
            return -1;
        }

        this->body = (char *)malloc(this->body_size);
        if (!this->body)
            return -1;

        this->body_received = 0;
    }

    size_t body_left = this->body_size - this->body_received;

    if (size > body_left)
    {
        errno = EBADMSG;
        return -1;
    }

    memcpy(this->body, buf, size);
    if (size < body_left)
        return 0;

    return 1;
}

}
~~~

The implementation of encode is very simple, in which two vectors are always, pointing to the head and the body respectively. Note that the iov\_base pointer must point to a member of the message class.   
When you use append, you should ensure that the 4-byte head is received completely before reading the message body. Moreover, we can't guarantee that the first append must contain a complete head, so the process is a little cumbersome.  
The append implements the size\_limit function, and an EMSGSIZE error will be returned if the size\_limit is exceeded. You can ignore the size_limit field if you don't need to limit the message size.  
Because we require the communication protocol is two way with a request and a response, users do not need to consider the so-called "TCP packet sticking" problem. The problem should be treated as an error message directly.  
Now, with the definition and implementation of messages, we can build a server and a client.

# Server and client definitions

With the request and response classes, we can build a server and a client based on this protocol. The previous example explains the type definitions related to an HTTP protocol:

~~~cpp
using WFHttpTask = WFNetworkTask<protocol::HttpRequest,
                                 protocol::HttpResponse>;
using http_callback_t = std::function<void (WFHttpTask *)>;

using WFHttpServer = WFServer<protocol::HttpRequest,
                              protocol::HttpResponse>;
using http_process_t = std::function<void (WFHttpTask *)>;
~~~

Similarly, for the protocol in this tutorial, there is no difference in the definitions of data types:

~~~cpp
using WFTutorialTask = WFNetworkTask<protocol::TutorialRequest,
                                     protocol::TutorialResponse>;
using tutorial_callback_t = std::function<void (WFTutorialTask *)>;

using WFTutorialServer = WFServer<protocol::TutorialRequest,
                                  protocol::TutorialResponse>;
using tutorial_process_t = std::function<void (WFTutorialTask *)>;
~~~

# server

There is no difference between this server and an ordinary HTTP server. We give priority to IPv6 startup, which does not affect the client requests in IPv4. In addition, the maximum request size is limited to 4KB.   
Please see [server.cc](/tutorial/tutorial-10-user_defined_protocol/server.cc) for the complete code.

# client

The logic of the client is to receive the user input from standard IO, construct a request, send it to the server and get the results. Here we use WFRepeaterTask to implement the repeating process, terminates if the user's input is empty. For the sake of security, we limit the packet size of the server reply to 4KB.   
The only thing that a client needs to know is how to generate a client task on a user-defined protocol. There are three interface options in [WFTaskFactory.h](/src/factory/WFTaskFactory.h):

~~~cpp
template<class REQ, class RESP>
class WFNetworkTaskFactory
{
private:
	using T = WFNetworkTask<REQ, RESP>;

public:
	static T *create_client_task(TransportType type,
								 const std::string& host,
								 unsigned short port,
								 int retry_max,
								 std::function<void (T *)> callback);

	static T *create_client_task(TransportType type,
								 const std::string& url,
								 int retry_max,
								 std::function<void (T *)> callback);

	static T *create_client_task(TransportType type,
								 const ParsedURI& uri,
								 int retry_max,
								 std::function<void (T *)> callback);

	static T *create_client_task(TransportType type,
								 const struct sockaddr *addr,
								 socklen_t addrlen,
								 int retry_max,
								 std::function<void (T *)> callback);

    ...
};
~~~

Among them, TransportType specifies the transport layer protocol, and the current options include TT\_TCP, TT\_UDP, TT\_SCTP, TT\_TCP\_SSL and TT\_SCTP\_SSL.   
There is little difference between the interfaces. In our example, the URL is not needed for the time being. We use a domain name and a port to create a task.   
The actual code is shown as follows. We inherited the WFTaskFactory class, but this derivation is not required.

~~~cpp
using namespace protocol;

class MyFactory : public WFTaskFactory
{
public:
    static WFTutorialTask *create_tutorial_task(const std::string& host,
                                                unsigned short port,
                                                int retry_max,
                                                tutorial_callback_t callback)
    {
        using NTF = WFNetworkTaskFactory<TutorialRequest, TutorialResponse>;
        WFTutorialTask *task = NTF::create_client_task(TT_TCP, host, port,
                                                       retry_max,
                                                       std::move(callback));
        task->set_keep_alive(30 * 1000);
        return task;
    }
};
~~~

You can see that we used the WFNetworkTaskFactory\<TutorialRequest, TutorialResponse> class to create a client task.   
Next, by calling the **set\_keep\_alive()** interface of the task, the connection is kept for 30 seconds after the communication is completed. Otherwise, the short connection will be used by default.   
The previous examples have explained the knowledge in other codes of the above client. Please see [client.cc](/tutorial/tutorial-10-user_defined_protocol/client.cc).

# How is the request on an built-in protocol generated

Currently, there are five built-in protocols in the framework: HTTP, Redis, MySQL, Kafka and DNS. Can we generate an HTTP or Redis task in the same way? For example:

~~~cpp
WFHttpTask *task = WFNetworkTaskFactory<protocol::HttpRequest, protocol::HttpResponse>::create_client_task(...);
~~~

Please note that an HTTP task generated in this way will lose a lot of functions. For example, it is impossible to identify whether to use persistent connection according to the header, and it is impossible to identify redirection, etc.   
Similarly, if a MySQL task is generated in this way, it may not run at all, because there is no login authentication process.   
A Kafka request may need to have complicated interactions with multiple brokers, so the request created in this way obviously cannot complete this process.   
This shows that the generation of one message in each built-in protocol is far more complicated than that in this example. Similarly, if you need to implement a communication protocol with more functions, there are still many codes to write.
