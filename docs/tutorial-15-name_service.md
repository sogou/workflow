# 自定义命名服务策略：name_service
# 示例代码
[tutorial-15-name_service.cc](/tutorial/tutorial-15-name_service.cc)

# 关于name_service
本示例通过一个用户定义文本文件来指定名称服务策略。文件格式定义与系统hosts文件兼容，目前也支持指向域名。例如：
~~~
127.0.0.1 www.myhost.com
192.168.10.10 host1
wwww.sogou.com sogou # 扩展功能，'sogou'指向'www.sogou.com'
~~~
用户在命令行输入抓取的URL和名称服务文件来抓取目标网页。如果输入URL的域名在文件中不存在，则正常使用DNS。

# 自定义名称服务策略
所有名称服务策略，从WFNSPolic派生。其唯一需要实现的是create_router_task函数。
~~~cpp
class MyNSPolicy : public WFNSPolicy
{
public:
    WFRouterTask *create_router_task(const struct WFNSParams *params, router_callback_t callback) override;
    ..
};
~~~
在这个示例里，我们并不需要引入很复杂的选取策略，只需要从一个文本文件把域名做转化。  
所以，我们可以把转化结果交给全局的dns resolver，让dns resolve产生真正的路由任务。
~~~cpp
WFRouterTask *MyNSPolicy::create_router_task(const struct WFNSParams *params, router_callback_t callback)
{
    WFDnsResolver *dns_resolver = WFGlobal::get_dns_resolver();

    if (params->uri.host)
    {
        FILE *fp = fopen(this->path.c_str(), "r");
        if (fp)
        {
            std::string dest = this->read_from_fp(fp, params->uri.host);
            if (dest.size() > 0)
            {
                /* Update the uri structure's 'host' field directly.
	               * You can also update the 'port' field if needed. */
	              free(params->uri.host);
                params->uri.host = strdup(dest.c_str());
            }

            fclose(fp);
         }
    }

    /* Simply, use the global dns resolver to create a router task. */
    return dns_resolver->create_router_task(params, std::move(callback));
}
~~~
其中read_from_fp函数从文本文件中读取信息并做转换，这个函数的实现大家可以直接看源代码。  
得到转换结果之后，用新的host覆盖原params里uri的host即可。最后，调用dns resover产生路由任务。

# 注册名称服务
Workflow里，可以给每个单独的域名指定一个名称服务策略。如果一个域名找不到指定策略，则使用默认。  
一般情况下，默认名称服务策略即是dns resolver。下面，我们把我定义好的策略注册到输入URL的域名上：
~~~cpp
int main()
{
    ...
    /* Create an naming policy. */
    MyNSPolicy *policy = new MyNSPolicy(filename);

    /* Get the global name service object.*/
    WFNameService *ns = WFGlobal::get_name_service();

    /* Add the our name with policy to global name service.
     * You can add mutilply names with one policy object. */
     ns->add_policy(name, policy);
    ...
}
~~~
其中，name为URL里的域名。这样的话，这个域名下的所有URL，都将使用我们自定义的名称服务策略了。  
在程序退出之前，我们也需要把这个策略从全局名称服务中删除，防止内存泄漏：
~~~cpp
int main()
{
    ...
    /* clean up */
    ns->del_policy(name);
    delete policy;
    return 0;
}
~~~
# 设置默认名称服务策略
在这个例子中，其实我们并没有修改默认名称服务策略。有些情况下，我们可能想让所有的host都使用这个名称服务策略。  
这种情况，我们也可以修改默认的策略，让这个策略对所有的host都生效。只需要调用全局名称服务的set_default_policy函数：
~~~cpp
int main()
{
    MyNSPolicy *policy = new MyNSPolicy(filename);
    WFNameService *ns = WFGlobal::get_name_service();
    ns->set_default_policy(policy);
    ...

    /* Reset default policy to dns resolver and clean up */
    ns->set_default_policy(WFGlobal::get_dns_resolver());
    delete policy;
    return 0;
}
~~~
