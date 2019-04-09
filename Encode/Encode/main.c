#define _CRT_SECURE_NO_WARNINGS
#include "itcast_asn1_der.h"
#include "itcastderlog.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>	
#define FILENAME "D:/char stream/stream.txt"
//要进行编码的结构体数据
typedef struct teacher
{
	char name[64];
	char addr[64];
	int len;
	int age;
}teacher_t;
//结构体编码函数
//const teacher_t *t 传入的要编码的数据源
//unsigned char **outData 存放编码后的数据源
//int *outDatalen 编码后的数据源的长度
int Encode(const teacher_t *t, unsigned char **outData, int *outDatalen)
{
	int ret = -1;
	ITCAST_ANYBUF *nodeHead = NULL;
	ITCAST_ANYBUF *nodeName = NULL;
	ITCAST_ANYBUF *nodeAddr = NULL;
	ITCAST_ANYBUF *nodeLen = NULL;
	ITCAST_ANYBUF *nodeAge = NULL;
	//对传入参数做容错判断
	if (NULL == t || NULL == outData || NULL == outDatalen)
	{
		printf("some parameters of Encode is wrong\n");
		goto err0;
	}
	//编码name
	ret = EncodeChar(&t->name, strlen(t->name), &nodeName);//将t->name转化为结构体nodeName
	if (0 != ret)
	{
		printf("EncodeChar name is failed\n");
		//不成功要释放空间
		goto err1;
	}
	//编码addr
	ret = EncodeChar(&t->addr, strlen(t->addr), &nodeAddr);//将t->addr转化为结构体nodeAddr
	if (0 != ret)
	{
		printf("EncodeChar addr is failed\n");
		//不成功要释放空间
		goto err1;
	}
	//编码len
	ret = DER_ItAsn1_WriteInteger(t->len, &nodeLen);//将t->len转化为结构体nodeLen
	if (0 != ret)
	{
		printf("DER_ItAsn1_WriteInteger len is failed\n");
		//不成功要释放空间
		goto err1;
	}
	//编码age
	ret = DER_ItAsn1_WriteInteger(t->age, &nodeAge);//将t->age转化为结构体nodeAge
	if (0 != ret)
	{
		printf("DER_ItAsn1_WriteInteger age is failed\n");
		//不成功要释放空间
		goto err1;
	}

	//将数据流连接成链表
	nodeName->next = nodeAddr;
	nodeAddr->next = nodeLen;
	nodeLen->next = nodeAge;
	nodeAge->next = NULL;

	//编码大的结构体
	ITCAST_ANYBUF *nodeOut = NULL;
	unsigned char *tmpdata = NULL;
	int tmplen = 0;
	nodeHead = nodeName;
	ret = DER_ItAsn1_WriteSequence(nodeHead, &nodeOut);
	if (0 != ret)
	{
		printf("DER_ItAsn1_WriteSequence nodeHead is failed\n");
		//不成功要释放空间
		goto err1;
	}
	//将字节流赋值到outData outDatalen
	tmpdata = (char*)malloc(nodeOut->dataLen + 1);
	memset(tmpdata, 0, sizeof(tmpdata));
	tmplen = nodeOut->dataLen;
	memcpy(tmpdata, nodeOut->pData, tmplen);
	*outData = tmpdata;
	*outDatalen = tmplen;
	//释放
#if 0
	if (NULL != nodeName)
	{
		DER_ITCAST_FreeQueue(nodeName);
	}
	if (NULL != nodeAddr)
	{
		DER_ITCAST_FreeQueue(nodeAddr);
	}
	if (NULL != nodeAge)
	{
		DER_ITCAST_FreeQueue(nodeAge);
	}
	if (NULL != nodeLen)
	{
		DER_ITCAST_FreeQueue(nodeLen);
	}
#else
	if (NULL != nodeHead)
	{
		DER_ITCAST_FreeQueue(nodeHead);
	}

	if (NULL != nodeOut)
	{
		DER_ITCAST_FreeQueue(nodeOut);
	}
#endif
	return 0;
err0:
	return 1;
err1:
	if (NULL != nodeName)
	{
		DER_ITCAST_FreeQueue(nodeName);
		return 2;
	}
	if (NULL != nodeAddr)
	{
		DER_ITCAST_FreeQueue(nodeAddr);
		return 2;
	}
	if (NULL != nodeAge)
	{
		DER_ITCAST_FreeQueue(nodeAge);
		return 2;
	}
	if (NULL != nodeLen)
	{
		DER_ITCAST_FreeQueue(nodeLen);
		return 2;
	}
	if (NULL != nodeOut)
	{
		DER_ITCAST_FreeQueue(nodeOut);
		return 2;
	}
}
//结构体解码函数
//const unsigned char *inData 编码后的数据流
//int inDatalen 编码胡的数据流长度
//teacher_t **t 存放数据流还原后的元原数据
int Uncode(const unsigned char *inData, int inDatalen, teacher_t **t)
{
	int ret = -1;
	teacher_t *tmp = NULL;
	ITCAST_ANYBUF *tmpdata = NULL;
	ITCAST_ANYBUF *nodehead = NULL;	
	ITCAST_ANYBUF *nodename = NULL;
	ITCAST_ANYBUF *nodeaddr = NULL;
	//ITCAST_ANYBUF *nodelen = NULL;
	//ITCAST_ANYBUF *nodeage = NULL;
	ITCAST_ANYBUF *nodetmp = NULL;
	//int tmplen = 0;
	//对传入参数做容错判断
	if (NULL == inData || inDatalen <= 0 || NULL == t)
	{
		printf("some parameters of Uncode is wrong\n");
		goto err0;
	}
	//将传进来的inData先转换为ITCAST_ANYBUF，为后续的解码做准备
	ret = DER_ITCAST_String_To_AnyBuf(&tmpdata, inData, inDatalen);
	if (0 != ret)
	{
		printf("DER_ITCAST_String_To_AnyBuf is failed\n");
		//不成功要释放空间
		goto err1;
	}
	//将转换为ITCAST_ANYBUF的数据流转换为大的结构体链表
	ret = DER_ItAsn1_ReadSequence(tmpdata, &nodehead);
	if (0 != ret)
	{
		printf("DER_ItAsn1_ReadSequence is failed\n");
		//不成功要释放空间
		goto err1;
	}
	tmp = (teacher_t*)malloc(sizeof(teacher_t));
	memset(tmp, 0, sizeof(teacher_t));
	//解码name
	nodetmp = nodehead;
	ret = DER_ItAsn1_ReadBitString(nodetmp, &nodename);
	if (0 != ret)
	{
		printf("DER_ItAsn1_ReadBitString nodename is failed\n");
		//不成功要释放空间
		goto err1;
	}
	memcpy(tmp->name, nodename->pData, nodename->dataLen);
	//ret = DecodeChar(nodetmp, &tmp->name, &(nodetmp->dataLen));
	//解码addr
	nodetmp = nodetmp->next;
	ret = DER_ItAsn1_ReadBitString(nodetmp, &nodeaddr);
	if (0 != ret)
	{
		printf("DER_ItAsn1_ReadBitString nodeaddr is failed\n");
		//不成功要释放空间
		goto err1;
	}
	memcpy(tmp->addr, nodeaddr->pData, nodeaddr->dataLen);
	//ret = DecodeChar(nodetmp, &tmp->addr, &(nodetmp->dataLen));
	//解码len
	nodetmp = nodetmp->next;
	ret = DER_ItAsn1_ReadInteger(nodetmp, &tmp->len);
	//解码age
	nodetmp = nodetmp->next;
	ret = DER_ItAsn1_ReadInteger(nodetmp, &tmp->age);

	*t = tmp;
#if 1
	//释放空间
	if (NULL != tmpdata)
	{
		DER_ITCAST_FreeQueue(tmpdata);
	}
	if (NULL != nodehead)
	{
		DER_ITCAST_FreeQueue(nodehead);
	}
	if (NULL != nodename)
	{
		DER_ITCAST_FreeQueue(nodename);
	}
	if (NULL != nodeaddr)
	{
		DER_ITCAST_FreeQueue(nodeaddr);
	}
#endif
	return 0;

err0:
	return 1;
err1:
	if (NULL != tmpdata)
	{
		DER_ITCAST_FreeQueue(tmpdata);
		return 2;
	}
	if (NULL != nodehead)
	{
		DER_ITCAST_FreeQueue(nodehead);
		return 2;
	}
	if (NULL != nodename)
	{
		DER_ITCAST_FreeQueue(nodename);
		return 2;
	}
	if (NULL != nodeaddr)
	{
		DER_ITCAST_FreeQueue(nodeaddr);
		return 2;
	}

}
//结构体内存释放函数
int mem_free(teacher_t **t)
{
	//1. 容错判断
	if (NULL == t || NULL == *t)
	{
		printf("some parameter are NULL\n");
		return 1;
	}

	//2. 如果结构体中包含指针  就必须先释放结构体中指针内存

	//3. 释放*t  free
	free(*t);

	//4. 置NULL
	*t = NULL;

	return 0;
}
//字节流保存函数
void Write_To_File(const char *filename, const unsigned char *Data, int Datalen)
{
	int ret = -1;
	FILE *fd = fopen(filename, "ab+");
	if (NULL == fd)
	{
		perror("fopen");
		return 1;
	}
	ret = fwrite(Data, 1, Datalen, fd);
	if (ret == 0)
	{
		printf("fwrite failed....\n");
		fclose(fd);
		return 1;
	}
	fclose(fd);
}

int main()
{
	int ret = -1;
	teacher_t Tin = { "lili", "china",1 ,18 };
	//编码参数
	char *Data = NULL;
	int Datalen = 0;
	//编码
	ret = Encode(&Tin, &Data, &Datalen);
	if (0 != ret)
	{
		printf("data encode failed\n");
		return 1;
	}
	else
	{
		printf("data encode successed\n");
		printf("Data:%s Datalen:%d\n", Data, Datalen);
		Write_To_File(FILENAME, Data, Datalen);
	}
#if 1
	//解码
	teacher_t *Tout = NULL;
	ret = Uncode(Data, Datalen, &Tout);
	if (0 != ret)
	{
		printf("data uncode failed\n");
		return 1;
	}
	else
	{
		printf("data uncode successed\n");
		printf("name:%s addr:%s len:%d age:%d\n", Tout->name, Tout->addr, Tout->len,Tout->age);
	}
	//判断编码前和解码后的数据是否一致
	if ((strcmp(Tin.name, Tout->name) == 0) && (strcmp(Tin.addr, Tout->addr) == 0))
	{
		printf("data encode and uncode successed\n");
	}
	else
	{
		printf("data encode and uncode failed\n");
	}
	free(Data);
	mem_free(&Tout); 
#endif
	system("pause");
	return 0;
}


