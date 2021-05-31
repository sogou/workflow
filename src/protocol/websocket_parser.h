#ifndef _WEBSOCKET_PARSER_H_
#define _WEBSOCKET_PARSER_H_

#define WS_HEADER_LENGTH_MAX	14
#define WS_SERVER_LENGTH_MIN	2
#define WS_CLIENT_LENGTH_MIN	6
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

enum
{
	WSStatusCodeUndefined			= 0,

	WSStatusCodeNormal				= 1000,
	WSStatusCodeGoingAway			= 1001,
	WSStatusCodeProtocolError		= 1002,
	WSStatusCodeUnsupported			= 1003,
	WSStatusCodeReserved			= 1004, // reserved
	WSStatusCodeNoStatus			= 1005, // reserved
	WSStatusCodeAbnomal				= 1006, // reserved
	WSStatusCodeUnsupportedData		= 1007,
	WSStatusCodePolicyViolation		= 1008,
	WSStatusCodeTooLarge			= 1009,
	WSStatusCodeMissExtention		= 1010,
	WSStatusCodeInternalError		= 1011,
//	WSStatusCodeServiceRestart		= 1012,
//	WSStatusCodeTryAgainLater		= 1013,
	WSStatusCodeTLSHandshake		= 1015, // reserved

	WSStatusCodeProtocolMax			= 2999,

	WSStatusCodeIANAMin				= 3000,
	WSStatusCodeIANAMax				= 3999,

	WSStatusCodeUserMin				= 4000,
	WSStatusCodeUserMax				= 4999,
};

typedef struct __websocket_parser
{
	char fin;
	char mask;
	int opcode;
	unsigned char masking_key[WS_MASKING_KEY_LENGTH];
	unsigned long long payload_length;
	unsigned char header_buf[WS_HEADER_LENGTH_MAX];
	void *payload_data;
	unsigned long long nreceived;
	int masking_key_offset;
	int nleft;
	int is_server;
	int status_code;
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

int websocket_parser_parse(websocket_parser_t *parser);

void websocket_parser_mask_data(websocket_parser_t *parser);

unsigned char *utf8_check(unsigned char *s, size_t len);

#ifdef __cplusplus
}
#endif

static inline void websocket_set_mask_key(unsigned int masking_key,
										  websocket_parser_t *parser)
{
	uint32_t *key = (uint32_t *)parser->masking_key;
	*key = masking_key;
	parser->mask = 1;
}

static inline void websocket_set_opcode(int opcode, websocket_parser_t *parser)
{
	parser->opcode = opcode;
}

#endif

