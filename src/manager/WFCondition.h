#ifndef _WFCONDITION_H_
#define _WFCONDITION_H_

#include <pthread.h>
#include "list.h"
#include "WFTask.h"

class WFCondition
{
public:
	WFCondition() :
		mutex(PTHREAD_MUTEX_INITIALIZER)
	{
		INIT_LIST_HEAD(&this->waiter_list);
	}

	WFCounterTask *create_wait_task(std::function<void (WFCounterTask *)> cb);
	WFCounterTask *create_timedwait_task(unsigned int microseconds,
										 std::function<void (WFCounterTask *)> cb);
	void signal();
	void broadcast();

public:
	pthread_mutex_t mutex;

private:
	struct list_head waiter_list;
};

#endif

