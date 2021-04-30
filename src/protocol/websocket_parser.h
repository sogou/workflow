#ifndef _WEBSOCKET_PARSER_H_
#define _WEBSOCKET_PARSER_H_

#define WS_HEADER_LENGTH_MAX	14
#define WS_HEADER_LENGTH_MIN	2
#define WS_MASKING_KEY_LENGTH	4

#include <stddef.h>
#include <stdint.h>

enum
{
	WebSocketFrameContinuation		= 0,
	WebSocketFrameText				= 1,
	WebSocketFrameBinary			= 2,
	WebSocketFrameConnectionClose	= 8,
	WebSocketFramePing				= 9,
	WebSocketFramePong				= 10,
};

typedef struct __websocket_parser
{
//	unsigned int fin : 1;
	char fin;
	char mask;
	char opcode;
//	unsigned int masking_key;
	unsigned char masking_key[WS_MASKING_KEY_LENGTH];
	char masking_key_offset;
	char nleft;
	unsigned long long payload_length;
	void *payload_data;
	unsigned long long nreceived;
	unsigned char header_buf[WS_HEADER_LENGTH_MAX];
//	unsigned char pos;
//	char mask_flag
} websocket_parser_t;

#ifdef __cplusplus
extern "C"
{
#endif

void websocket_parser_init(websocket_parser_t *parser);
void websocket_parser_deinit(websocket_parser_t *parser);
int websocket_parser_append_message(const void *buf, size_t *n,
									websocket_parser_t *parser);

int websocket_parser_decode_payload_length(websocket_parser_t *parser);

void websocket_parser_encode_payload_length(websocket_parser_t *parser);

void websocket_parser_mask_data(websocket_parser_t *parser);

void websocket_parser_unmask_data(websocket_parser_t *parser);

/*
int decode_payload_length(unsigned long long *length, const unsigned char **pos,
						  const unsigned char *end);

int encode_payload_length(unsigned long long length, const unsigned char **pos,
						  const unsigned char *end);
*/

#ifdef __cplusplus
}
#endif

static inline void websocket_set_mask_key(websocket_parser_t *parser, unsigned int masking_key)
{
	uint32_t *key = (uint32_t *)parser->masking_key;
	*key = masking_key;
	parser->mask = 1;
}

static inline void websocket_set_opcode(websocket_parser_t *parser, char opcode)
{
	parser->opcode = opcode;
}

#endif

