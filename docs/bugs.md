# 已知BUG列表

### OpenSSL 1.1.1及以下，出现网络任务状态为WFT_STATE_SYS_ERROR，错误为0。
这是OpenSSL 1.1.1及以下的bug，在SSL_get_error()为SSL_ERROR_SYSCALL时，errno被置为0。由于框架会把SSL_ERROR_SYSCALL转为系统错误，这会导致我们得到一个错误码0的系统错误：
~~~cpp
void callback(WFHttpTask *task)
{
    int state = task->get_state();
    int error = task->get_error();
    printf("%d, %d\n", state, error);  // 此处得到1，0，其中1是WFT_STATE_SYS_ERROR。
}
~~~
显然只有在SSL通信下可能出现在这个问题。这个bug在OpenSSL 3.0里被修复，建议升级到OpenSSL 3.0或以上。  
相关issue：https://github.com/openssl/openssl/issues/12416
### 访问HTTPS网页，当打开TLS SNI并使用upstream时出现SSL error。
当我们创建Http任务，http header里的Host域填写的是原始URL里的host部分。例如：
~~~cpp
void f()
{
    auto *task = WFTaskFactory::create_http_task("https://sogou/index.html", 0, 0, nullptr);
}
~~~
这时候http request里的Host必然填写的是"sogou"。此时如果sogou是一个upstream名，指向域名www.sogou.com。并且我们开启了TLS SNI，那么SNI server name信息就是www.sogou.com，与http header里的Host是不一致的，会导致SSL错误。  
要解决这个问题，用户可以在通过设置prepare函数，在发送请求前修改Host，让它与最终URL里的一致：
~~~cpp
void f();
{
    auto *task = WFTaskFactory::create_http_task("https://sogou/index.html", 0, 0, nullptr);
    static_cast<WFClientTask<protocol::HttpRequest, protocol::HttpResponse> *>(task)->set_prepare([](WFHttpTask *task){
        auto *t = static_cast<WFComplexClientTask<protocol::HttpRequest, protocol::HttpResponse> *>(task);
        task->get_req()->set_header_pair("Host", t->get_current_uri()->host);  // 这里得到实际uri里的host。
    });
}
~~~
只有打开了TLS SNI功能并使用upstream会出这个不一致问题。当然，很多时候我们配置upstream来访问http网站，也需要做这个修改，否则对方可能不会接受你的Host信息。
