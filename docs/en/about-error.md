# About error handling

Error handling is an important and complex problem in any software system. Within our framework, error handling is ubiquitous and extremely cumbersome.   
In the interfaces we exposed to users, we try to make things as simple as possible, but users still inevitably need to know some error messages.

### Disabling C++ exceptions

C++ exceptions are not used in our framework. When you compile your own code, it is best to add **-fno-exceptions** flag to reduce the code size.   
According to the common practice in the industry, we ignore the possibility of the failure of **new** operation, and avoid using new to allocate large blocks of memory internally. And there are error checks in memory allocation in C style.

### About factory functions

From the previous examples, you can see that all task and series are generated from two factory classes, WFTaskFactory or Workflow.   
These factory classes, as well as more factory class interfaces that we may encounter in the future, ensure success. In other words, they never return NULL. And you do not need to check the return value.   
To achieve this goal, even when the URL is illegal, the factory still generates the task normally. And you will get the error in the callback of the task.

### States and error codes of a task

In the previous examples, you often see such codes in the callback:

~~~cpp
void callback(WFXxxTask *task)
{
    int state = task->get_state();
    int error = task->get_error();
    ...
}
~~~

in which, the state indicates the end state of a task. [WFTask.h](/src/factory/WFTask.h) contains all possible states:

~~~cpp
enum
{
    WFT_STATE_UNDEFINED = -1,
    WFT_STATE_SUCCESS = CS_STATE_SUCCESS,
    WFT_STATE_TOREPLY = CS_STATE_TOREPLY,        /* for server task only */
    WFT_STATE_NOREPLY = CS_STATE_TOREPLY + 1,    /* for server task only */
    WFT_STATE_SYS_ERROR = CS_STATE_ERROR,
    WFT_STATE_SSL_ERROR = 65,
    WFT_STATE_DNS_ERROR = 66,                    /* for client task only */
    WFT_STATE_TASK_ERROR = 67,
    WFT_STATE_ABORTED = CS_STATE_STOPPED         /* main process terminated */
};
~~~

##### Please note the following states:

* SUCCESS: the task is successfully completed. The client receives the complete reply, or the server writes the reply completely into the send buffer (but there is no guarantee that the peer will receive it).
* SYS\_ERROR: system error. In this case, use **task->get\_error()** to get the system error code **errno**.
  * When **get\_error()** gets ETIMEDOUT, you can call **task->get\_timeout\_reason()** to get the timeout reasons.
* DNS\_ERROR: DNS resolution error. Use **get\_error()** to get the return code of **getaddrinfo()**. For DNS, please see the article for details [about-dns.md](/docs/en/about-dns.md). 
  * The server task never has a DNS\_ERROR.
* SSL\_ERROR: SSL error. Use **get\_error()** to get the return value of **SSL\_get\_error()**.
  * Currently SSL error information is not complete, and you can not get the value of **ERR\_get\_error()**. Therefore, basically there are three possible return value of **get\_error()**:
    * SSL\_ERROR\_ZERO\_RETURN, SSL\_ERROR\_X509\_LOOKUP, SSL\_ERROR\_SSL.
  * We will consider adding more detailed SSL error information in the future versions.
* TASK\_ERROR: task errors. Common errors include illegal URL, login failure, etc. [WFTaskError.h](/src/factory/WFTaskError.h) lists the return values of **get\_error()**.

##### You do not need to pay attention to the following states:

* UNDEFINED: Client tasks that have just been created and have not yet been run are in UNDEFINED state.
* TOREPLY: Server tasks that have not sent replies or called **task->noreply()** are in TOREPLY state.
* NOREPLY: Server tasks that have called **task->noreply()** are always in NOREPLY state. The callback of these tasks are also in NOREPLY state. And the connection will be closed.

### Other error handling requirements

In addition to the error handling of the task itself, you also need to check the errors of the message interfaces of various protocols. Generally, these interfaces indicate errors by returning false, and show the error reasons in the errno.   
In addition, you may encounter more complicated error messages when you use some complex operations. You will learn them in detailed documents.
