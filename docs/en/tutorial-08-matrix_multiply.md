# User-defined computing tasks: matrix\_multiply

# Sample code

[tutorial-08-matrix\_multiply.cc](/tutorial/tutorial-08-matrix_multiply.cc)

# About matrix\_multiply

The program multiplies two matrices and prints the results on the screen.   
The main purpose of the example is to show how to implement a user-defined CPU computing task.

# About computing tasks

You need to provide three types of basic information when you define a computer task: INPUT, OUTPUT, and routine.   
INPUT and OUTPUT are two template parameters, which can be of any type. routine means the process from INPUT to OUTPUT, which is defined as follows:

~~~cpp
template <class INPUT, class OUTPUT>
class __WFThreadTask
{
    ...
    std::function<void (INPUT *, OUTPUT *)> routine;
    ...
};
~~~

It can be seen that routine is a simple computing process from INPUT to OUTPUT. The INPUT pointer is not necessarily be const, but you can also pass the function of const INPUT \*.   
For example, to implement an adding task, you can:

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

In the example of matrix multiplication, the input is two matrices and the output is one matrix. They are defined as follows:

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

As the input matrices may be illegal in matrix multiplication, so there is an error field in the output to indicate errors.

# Generating computing tasks

After you define the types of input and output and the algorithm process, you can use  WFThreadTaskFactory  to generate a computing task.   
In [WFTaskFactory.h](/src/factory/WFTaskFactory.h), the computing task factory is defined as follows:

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
There are two interfaces for creating tasks here. The second interface supports the user to pass in the task running time limit, we will introduce this function in the next section. Slightly different from the previous network factory class or the algorithm factory class, this factory requires two template parameters: INPUT and OUTPUT.   
queue\_name is explained in the previous example. routine is the computation process, and callback means the callback.   
In our example, we see this call:

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

After the task is generated, use **get\_input()** interface to get the pointer of the input data. This is similar to the **get\_req()** in a network task.   
The start and the end of a task is the same as those of a network task. Similarly, the callback is very simple:

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

You can ignore the the possibility of failure in the ordinary computing tasks, and the end state is always SUCCESS.   
The callback simply prints out the input and the output. If the input data are illegal, the error will be printed out.

# Computing task with running time limit
Obviously, our framework can not interrupt a computing task because it's a user function, and the users have to make sure the function will terminate normally. But we support users to create a computing task with a running time limit, and if the task doesn't finish within this time, the task will  callback directly:
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
This create_thread_task function needs to pass two more parameters, seconds and nanoseconds. If the running time of func reaches the seconds+nanosconds time limit, the task callback directly, and the state is WFT_STATE_ABORTED. But the task routine will continue to run till the end.

# Symmetry of the algorithm and the protocol

In our system, algorithms and protocols are highly symmetrical on a very abstract level.   
There are thread tasks with user-defined algorithms,  obviously there are network tasks with user-defined protocols.   
A user-defined algorithm requires the user to provide the algorithm procedure, and a user-defined protocol requires the user to provide the procedure of serialization and deserialization. You can see an introduction in [Simple client/server based on user-defined protocols](/tutorial-10-user_defined_protocol.md)   
For the user-defined algorithms and the user-defined protocols, both must be very pure .   
For example, an algorithm is just a conversion procedure from INPUT to OUPUT, and the algorithm does not know the existence of task, series, etc.   
The implementation of an HTTP protocol only cares about serialization and deserialization, and does not need to care about the task definition. Instead, the HTTP protocol is referred to in an http task.

# Composite features of thread tasks and network tasks

In this example, we use WFThreadTaskFactory to build a thread task. This is the simplest way to get a computing task, and it is sufficient in most cases.   
Similarly, you can simply define a server and a client with a user-defined protocol.   
However, in the previous example, we can use the algorithm factory to generate a parallel sorting task, which is obviously not possible with a routine.   
For a network task, such as a Kafka task, interactions with several machines may be required to get results, but it is completely transparent to users.   
Therefore, our tasks are composite. If you use our framework skillfully, you can design many composite components.
