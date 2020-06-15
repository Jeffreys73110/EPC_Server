#ifndef __FUNC_H__
#define __FUNC_H__

#include <stdio.h>
#include <algorithm> // std::min

#define LINE_TRACE() printf("\033[34m[LineTrace]\033[0m] %d @ %s\n", __LINE__, __FILE__)
#define RETURN                                                          \
	printf("\033[34m[LineTrace]\033[0m %d @ %s\n", __LINE__, __FILE__); \
	return
#define TestMsg_TRACE(...)                 \
	printf("\033[1;34m[TestMsg]\033[0m "); \
	printf(__VA_ARGS__)

// PrintBinary
#define PrintBinary_ENABLE true
static int PrintBinary(const unsigned char *msg, int len)
{
#if PrintBinary_ENABLE
	for (int i = 0, j = 0, l = 0; i < len; i += 16)
	{
		printf("  ");
		for (j = 0, l = std::min(len - i, 8); j < l; j++)
			printf("%02x ", (unsigned char)msg[i + j]);
		if (l <= 0)
			continue;
		printf(" ");
		for (j = 0, l = std::min(len - i - 8, 8); j < l; j++)
			printf("%02x ", (unsigned char)msg[i + j + 8]);
		printf("\n");
	}
	printf("\n\n");
#endif
	return 0;
}

#define GetBinaryToHexStr(msg, len) _GetBinaryToHexStr(msg, len).c_str()
static std::string _GetBinaryToHexStr(const unsigned char *msg, int len)
{
	const char hex[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	char buf[32] = "";
	int i;

	for (i = 0; i < len; i++)
	{
		buf[i * 2] = hex[(msg[i] & 0xf0) >> 4];
		buf[i * 2 + 1] = hex[msg[i] & 0x0f];
	}
	buf[i * 2] = 0;
	return buf;

	// const char hex[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	// char buf[32];
	// std::string	str;
	// str.clear();
	// int i;

	// for (i=0; i<len; i++)
	// {
	// str.push_back(hex[(msg[i]&0xf0)>>4]);
	// str.push_back(hex[msg[i]&0x0f]);
	// }
	// str.push_back('\0');
	// return str;
}

#endif // __FUNC_H__