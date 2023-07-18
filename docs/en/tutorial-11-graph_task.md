# Direct Acyclic Graph (DAG)：graph_task
# Sample code

[tutorial-11-graph_task.cc](/tutorial/tutorial-11-graph_task.cc)

# About graph_task

The graph_task example demonstrates how to implement more complex inter-task dependencies by building a DAG.

# Create tasks in the DAG

In this tutorial, we create a timer task, two http fetching task, and a 'go' task. Timer task executes a delay of 1 second before 
fetching, http tasks fetch the home page of 'sogou' and 'baidu' in parallel, and after all of that, go task will print the fetching result.  
The dependencies of the tasks are:
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

# Create the graph task

Graph is a kind of task as well. We can create a graph task by this function：
~~~cpp
class WFTaskFactory
{
public:
    static WFGraphTask *create_graph_task(graph_callback_t callback);
    ...
};
~~~
The graph is a empty graph after it's creation. Of course you may run an empty graph and will get to it callback immediately.

# Create graph nodes

We'v got 4 orindary tasks, which can not been added to the graph directly but need to be turned into graph nodes:
~~~cpp
{
   /* Create graph nodes */
    WFGraphNode& a = graph->create_graph_node(timer);
    WFGraphNode& b = graph->create_graph_node(http_task1);
    WFGraphNode& c = graph->create_graph_node(http_task2);
    WFGraphNode& d = graph->create_graph_node(go_task);
}
~~~
The ``create_graph_node`` interface of WFGraphTask creates a graph node that refers to a task. And we can use the references of 
graph nodes to specify the dependencies of them. Otherwise, they are all standalone nodes, and will run in parallel when the 
graph task is started.

# Build the graph
By using the '-->' or '<--' operators, we can specify the dependencies:
~~~cpp
{
   /* Build the graph */
    a-->b;
    a-->c;
    b-->d;
    c-->d;
}
~~~
And now we'v built the graph that we described. And we can use it like an orindary task.  
Also, any of the following codes is legal and equivalent:
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

# Data passing

Because the tasks in a graph don't share a same series, there is no general method for passing data between graph nodes.

# Acknowledgement

Some designs are inspired by [taskflow](https://github.com/taskflow/taskflow).

