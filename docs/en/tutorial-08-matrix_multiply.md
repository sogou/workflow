# User-defined computing tasks: matrix\_multiply

# Sample code

[tutorial-08-matrix\_multiply.cc](../tutorial/tutorial-08-matrix_multiply.cc)

# About matrix_multiply

The program multiplies two matrices and displays the results on the console.   
The main purpose of the example is to show how to implement a user-defined CPU computing task.

# About computing tasks

A computing task has three arguments: INPUT, OUTPUT, and routine.   
INPUT and OUTPUT are two template parameters that can hold any type, and a routine is the process from INPUT to OUTPUT. A computing task is defined as follows:

~~~cpp
template <class INPUT, class OUTPUT>
class __WFThreadTask
{
    ...
    std::function<void (INPUT *, OUTPUT *)> routine;
    ...
};
~~~

You can see that routine is a simple computing process from INPUT to OUTPUT. The INPUT pointer is not necessarily be const, but you can pass const INPUT \*.   
For example, to implement a task that adds two numbers, you can use the follow code:

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

In matrix multiplication, the input includes two matrices and the output is one matrix. They are defined as follows:

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

As the input matrices may be incompatible in matrix multiplication, there is an error field in the output to indicate that error.

# Generating computing tasks

After you define the types of input and output and the algorithm process, you can use WFThreadTaskFactory to generate a computing task.   
In [WFTaskFactory.h](../src/factory/WFTaskFactory.h), the calculation factory is defined as follows:

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
    ...
};
~~~

Slightly different from the previous network factory class or the algorithm factory class, this class requires two template parameters: INPUT and OUTPUT.   
queue\_name is explained in the previous example. routine is the computing process, and the callback means the callback of the function.   
In the example, there is a call:

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

After the task is generated, you can use **get\_input()** interface to get the pointer of the input data. This is similar to the **get\_req()** in a network task.   
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

You can ignore the possibility of failure in ordinary computing tasks, and the end state is always SUCCESS.   
The callback simply prints out the input and the output. If the input data are illegal, the error will be printed out.

# Symmetry of the algorithm and the protocol

In our system, algorithms and protocols are highly symmetrical on a very abstract level.   
There are thread tasks with user-defined algorithms, and obviously there are network tasks with user-defined protocols.   
A user-defined algorithm requires a user to provide the  procedure for algorithm implementation, and a user-defined protocol requires a user to provide the procedures for serialization and deserialization. You can see an introduction in [Simple client/server based on user-defined protocols](./tutorial-10-user_defined_protocol.md)   
For user-defined algorithms and user-defined protocols, both algorithms and protocols must be very pure and have single responsibility.   
For example, an algorithm is just a conversion procedure from INPUT to OUPUT, and the algorithm does not care about the existence of task, series, and etc.   
The implementation of an HTTP protocol only cares about serialization and deserialization, and does not need to care about the task. Instead, an HTTP task refers to the HTTP protocol.

# Compositionality of thread tasks and network tasks

In this example, we use WFThreadTaskFactory to build a thread task. This is the simplest way to get a computing task, and it is sufficient in most cases.   
Similarly, you can simply define a server and a client with a user-defined protocol.   
However, in the previous example, we use the algorithm factory to generate a parallel sorting task, which is obviously not possible with a routine.   
For a network task, such as a Kafka task, interactions with several machines may be required to get results, but it is completely transparent to users.   
Therefore, our tasks are composite. If you use our framework skillfully, you can design a lot of composite  components.