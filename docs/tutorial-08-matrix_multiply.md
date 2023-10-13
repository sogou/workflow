# 自定义计算任务：matrix_multiply
# 示例代码

[tutorial-08-matrix_multiply.cc](/tutorial/tutorial-08-matrix_multiply.cc)

# 关于matrix_multiply

程序执行代码里两个矩阵的乘法，并将相乘结果打印在屏幕上。  
示例的主要目的是展现怎么实现一个自定义CPU计算任务。

# 定义计算任务

定义计算任务需要提供3个基本信息，分别为INPUT，OUTPUT，和routine。  
INPUT和OUTPUT是两个模板参数，可以是任何类型。routine表示从INPUT到OUTPUT的过程，定义如下：  
~~~cpp
template <class INPUT, class OUTPUT>
class __WFThreadTask
{
    ...
    std::function<void (INPUT *, OUTPUT *)> routine;
    ...
};
~~~
可以看出routine是一个简单的从INPUT到OUTPUT的计算过程。INPUT指针不要求是const，但用户也可以传const INPUT *的函数。  
比如一个加法任务，就可这么做：
~~~cpp
struct add_input
{
    int x;
    int y;
};

struct add_ouput
{
    int res;
};

void add_routine(const add_input *input, add_output *output)
{
    output->res = input->x + input->y;
}

typedef WFThreadTask<add_input, add_output> add_task;
~~~
在我们的矩阵乘法的示例里，输入是两个矩阵，输出为一个矩阵。其定义如下：
~~~cpp
namespace algorithm
{

using Matrix = std::vector<std::vector<double>>;

struct MMInput
{
    Matrix a;
    Matrix b;
};

struct MMOutput
{
    int error;
    size_t m, n, k;
    Matrix c;
};

void matrix_multiply(const MMInput *in, MMOutput *out)
{
    ...
}

}
~~~
矩阵乘法存在有输入矩阵不合法的问题，所以output里多了一个error域，用来表示错误。

# 生成计算任务

定义好输入输出的类型，以及算法的过程之后，就可以通过WFThreadTaskFactory工厂来产生计算任务了。  
在[WFTaskFactory.h](../src/factory/WFTaskFactory.h)里，计算工厂类的定义如下：
~~~cpp
template <class INPUT, class OUTPUT>
class WFThreadTaskFactory
{
private:
    using T = WFThreadTask<INPUT, OUTPUT>;

public:
    static T *create_thread_task(const std::string& queue_name,
                                 std::function<void (INPUT *, OUTPUT *)> routine,
                                 std::function<void (T *)> callback);

    static T *create_thread_task(time_t seconds, long nanoseconds,
                                 const std::string& queue_name,
                                 std::function<void (INPUT *, OUTPUT *)> routine,
                                 std::function<void (T *)> callback);
    ...
};
~~~
这里包含两个创建任务的接口。第二个接口支持用户传入一下任务运行时间限制，我们在一下节介绍这个功能。  
与之前的网络工厂类或算法工厂类略有不同，这个类需要INPUT和OUTPUT两个模板参数。  
queue_name相关的知识在上一个示例里已经有介绍。routine就是你的计算过程，callback是回调。  
在我们的示例里，我们看到了这个调用的使用：
~~~cpp
using MMTask = WFThreadTask<algorithm::MMInput,
                            algorithm::MMOutput>;

using namespace algorithm;

int main()
{
    typedef WFThreadTaskFactory<MMInput, MMOutput> MMFactory;
    MMTask *task = MMFactory::create_thread_task("matrix_multiply_task",
                                                 matrix_multiply,
                                                 callback);

    MMInput *input = task->get_input();

    input->a = {{1, 2, 3}, {4, 5, 6}};
    input->b = {{7, 8}, {9, 10}, {11, 12}};
    ...
}
~~~
产生了task之后，通过get_input()接口得到输入数据的指针。这个可以类比网络任务的get_req()。  
任务的发起和结束什么，与网络任务并没有什么区别。同样，回调也很简单：
~~~cpp
void callback(MMTask *task)     // MMtask = WFThreadTask<MMInput, MMOutput>
{
    MMInput *input = task->get_input();
    MMOutput *output = task->get_output();

    assert(task->get_state() == WFT_STATE_SUCCESS);

    if (output->error)
        printf("Error: %d %s\n", output->error, strerror(output->error));
    else
    {
        printf("Matrix A\n");
        print_matrix(input->a, output->m, output->k);
        printf("Matrix B\n");
        print_matrix(input->b, output->k, output->n);
        printf("Matrix A * Matrix B =>\n");
        print_matrix(output->c, output->m, output->n);
    }
}
~~~
普通的计算任务可以忽略失败的可能性，结束状态肯定是SUCCESS。  
callback里简单打印了输入输出。如果输入数据不合法，则打印错误。

# 带运行时间限制的计算任务

显然，我们的框架无法打断用户的计算任务，因为用户的计算任务是一个函数，用户需要自行确保函数可以正常结束。  
但我们支持用户指定一个时间限制，当计算无法在指定时间内完成，任务可以提前回到callback。带运行时间限制的接口定义如下：
~~~cpp
template <class INPUT, class OUTPUT>
class WFThreadTaskFactory
{
private:
    using T = WFThreadTask<INPUT, OUTPUT>;

public:
    static T *create_thread_task(time_t seconds, long nanoseconds,
                                 const std::string& queue_name,
                                 std::function<void (INPUT *, OUTPUT *)> routine,
                                 std::function<void (T *)> callback);
    ...
};
~~~
参数seconds和nanoseconds构成了运行时限。在这里，nanoseconds的取值范围在\[0,1000000000)。  
当任务无法在运行时限内结束，会直接回到callback，并且任务的状态为WFT_STATE_SYS_ERROR且错误码为ETIMEDOUT。  
还是用matrix_multiply的例子，我们可以这样写：
~~~cpp
void callback(MMTask *task)     // MMtask = WFThreadTask<MMInput, MMOutput>
{
    MMInput *input = task->get_input();
    MMOutput *output = task->get_output();

    if (task->get_state() == WFT_STATE_SYS_ERROR && task->get_error() == ETIMEDOUT)
    {
        printf("Run out of time.\n");
        return;
    }

    assert(task->get_state() == WFT_STATE_SUCCESS)

    if (output->error)
        printf("Error: %d %s\n", output->error, strerror(output->error));
    else
    {
        printf("Matrix A\n");
        print_matrix(input->a, output->m, output->k);
        printf("Matrix B\n");
        print_matrix(input->b, output->k, output->n);
        printf("Matrix A * Matrix B =>\n");
        print_matrix(output->c, output->m, output->n);
    }
}

using namespace algorithm;

int main()
{
    typedef WFThreadTaskFactory<MMInput, MMOutput> MMFactory;
    MMTask *task = MMFactory::create_thread_task(0, 1000000,
                                                 "matrix_multiply_task",
                                                 matrix_multiply,
                                                 callback);

    MMInput *input = task->get_input();

    input->a = {{1, 2, 3}, {4, 5, 6}};
    input->b = {{7, 8}, {9, 10}, {11, 12}};
    ...
}
~~~
上面的示例，限制了任务运行时间不超过1毫秒，否则，以WFT_STATE_SYS_ERROR的状态返回。  
再次提醒，我们并不会中断用户的实际运行函数。当任务超时并callback，计算函数还会一直运行直到结束。  
如果用户希望函数不再继续执行，需要在代码中自行加入检查点来实现这样的功能。可以在INPUT里加入flag，例如：
~~~cpp
void callback(MMTask *task)     // MMtask = WFThreadTask<MMInput, MMOutput>
{
    if (task->get_state() == WFT_STATE_SYS_ERROR && task->get_error() == ETIMEDOUT)
    {
        task->get_input()->flag = true;
        printf("Run out of time.\n");
        return;
    }
    ...
}

void matrix_multiply(const MMInput *in, MMOutput *out)
{
    while (!in->flag)
    {
        ....
    }
}
~~~

# 算法与协议的对称性

在我们的体系里，算法与协议在一个非常抽象的层面上是具有高度对称性的。  
有自定义算法的线程任务，那显然也存在自定义协议的网络任务。  
自定义算法要求提供算法的过程，而自定义协议则需要用户提供序列化和反序列化的过程，[简单的用户自定义协议client/server](./tutorial-10-user_defined_protocol.md)有介绍。  
无论是自定义算法还是自定义协议，我们都必须强调算法和协议都是非常纯粹的。  
例如算法就是一个从INPUT到OUPUT的转换过程，算法并不知道task，series等的存在。  
HTTP协议的实现上，也只关心序列化反序列化，无需要关心什么是task。而是在http task里去引用HTTP协议。  

# 线程任务与网络任务的复合性

在这个示例里，我们通过WFThreadTaskFactory构建了一个线程任务。可以说这是一种最简单的计算任务构建，大多数情况下也够用了。  
同样，用户可以非常简单的定义一个自有协议的server和client。  
但在上一个示例里我们看到，我们可以通过算法工厂产生一个并行排序任务，这显然不是通过一个routine就能做到的。  
对于网络任务，比如一个kafka任务，可能要经过与多台机器的交互才能得到结果，但对用户来讲是完全透明的。  
所以，我们的任务都是具有复合性的，如果你熟练使用我们的框架，可以设计出很多复杂的组件出来。
