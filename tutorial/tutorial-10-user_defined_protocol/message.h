#ifndef _TUTORIALMESSAGE_H_
#define _TUTORIALMESSAGE_H_

#include <stdlib.h>
#include "workflow/ProtocolMessage.h"

namespace protocol
{

class TutorialMessage : public ProtocolMessage
{
private:
	virtual int encode(struct iovec vectors[], int max);
	virtual int append(const void *buf, size_t size);

public:
	int set_message_body(const void *body, size_t size);

	void get_message_body_nocopy(void **body, size_t *size)
	{
		*body = this->body;
		*size = this->body_size;
	}

protected:
	char head[4];
	size_t head_received;
	char *body;
	size_t body_received;
	size_t body_size;

public:
	TutorialMessage()
	{
		this->head_received = 0;
		this->body = NULL;
		this->body_size = 0;
	}

	TutorialMessage(TutorialMessage&& msg);
	TutorialMessage& operator = (TutorialMessage&& msg);

	virtual ~TutorialMessage()
	{
		free(this->body);
	}
};

using TutorialRequest = TutorialMessage;
using TutorialResponse = TutorialMessage;

}

#endif

