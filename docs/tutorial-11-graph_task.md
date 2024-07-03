# 有向无环图（DAG）的使用：graph_task
# 示例代码

[tutorial-11-graph_task.cc](/tutorial/tutorial-11-graph_task.cc)

# 关于graph_task

graph_task示例通过建立一个有向无环图，演示如何用workflow框架实现更加复杂的任务间依赖关系。

# 创建DAG中的任务

DAG中的任务，可以是workflow框架的任何一种任务。在本示例中，我们创建了一个timer任务，两个http任务，以及一个go任务。  
Timer执行一秒的等待，http1和http2分别抓取sogou和baidu的首页，go任务打印结果。它们之间的依赖关系如下：
~~~
            +-------+          
      +---->| Http1 |-----+   
      |     +-------+     |
 +-------+              +-v--+ 
 | Timer |              | Go | 
 +-------+              +-^--+ 
      |     +-------+     |    
      +---->| Http2 |-----+    
            +-------+          
~~~
创建DAG中任务的方法与创建普通任务的方法没有区别，这里不再展开。

# 创建图任务

DAG图在我们的框架里也是一种任务，通过以下代码，我们可以创建一个图任务：
~~~cpp
{
    WFGraphTask *graph = WFTaskFactory::create_graph_task([](WFGraphTask *) {
            printf("Graph task complete. Wakeup main process\n");
            wait_group.done();
        });
}
~~~
可以看到，图任务的类型为WFGraphTask，创建函数只有一个参数，即任务的回调。显然一个新建的图任务，是一张空图。

# 创建图节点

接下来，我们需要通过之前创建的4个普通任务（timer，http_task1，http_task2，go_task），产生4个图节点：
~~~cpp
{
   /* Create graph nodes */
    WFGraphNode& a = graph->create_graph_node(timer);
    WFGraphNode& b = graph->create_graph_node(http_task1);
    WFGraphNode& c = graph->create_graph_node(http_task2);
    WFGraphNode& d = graph->create_graph_node(go_task);
}
~~~
WFGraphTask的create_graph_node接口，产生一个图节点并返回节点的引用，用户通过这个节点引用来建立节点之间的依赖。  
如果我们不为节点建立依赖直接运行图任务，那么显然所有节点都是孤立节点，将全部并发执行。

# 建立依赖
通过非常形象的'-->'运算符，我们可以建立节点的依赖关系：
~~~cpp
{
   /* Build the graph */
    a-->b;
    a-->c;
    b-->d;
    c-->d;
}
~~~
这样我们就建立起了上述结构的DAG图啦。  
除’—>’运算符，我们同样支持’<—‘。并且它们都可以连着写。所以，以下程序都是合法且等价的：
~~~cpp
{
    a-->b-->d;
    a-->c-->d;
}
~~~
~~~cpp
{
    d<--b<--a;
    d<--c<--a;
}
~~~
~~~cpp
{
    d<--b<--a-->c-->d;
}
~~~
接下来直接运行graph，或者把graph放入任务流中就可以运行啦，和一般的任务没有区别。  
当然，把一个图任务变成另一个图的节点，也是完全正确的行为。

# 取消后继节点

在图任务里，我们扩展了series的cancel操作，这个操作会取消该节点的所有后继结点。  
取消操作一般在节点任务的callback里执行，例如：
~~~cpp
int main()
{
    WFGraphTask *graph = WFTaskFactory::create_graph_task(graph_callback);
    WFHttpTask *task = WFTaskFactory::create_http_task(url, 0, 0, [](WFHttpTask *t){
        if (t->get_state() != WFT_STATE_SUCCESS)
            series_of(t)->cancel();
    });
    WFGraphNode& a = graph->create_graph_node(task);
    WFGraphNode& b = ...;
    WFGraphNode& c = ...;
    WFGraphNode& d = ...;
    a-->b-->c;
    b-->d;
    graph->start();
    ...
}
~~~
注意取消后继节点的操作是递归的，这个例子里，如果http任务失败，b,c,d三个节点的任务都会被取消。

# 数据传递

图节点之间目前没有统一的数据传递方法，它们并不共享某一个series。因此，节点间数据传递需要用户解决。

# 致谢

部分思路来自于[taskflow](https://github.com/taskflow/taskflow)项目。

