#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <locale.h>


/********************************************************************
说明:FileSign和pSectionTable结构体用来记录PE结构中的关键字段
当想要操作ImageBuffer时,结构体中的指针全部失效,但是字段并不会发生变化,所以依然可以读取


以下函数都有各自的说明,填入参数即可,如若添加新节,请将新节大小的声明写入main方法的SizeOfNewSection中

*********************************************************************/










//打开文件，分配缓冲区，返回文件缓冲区指针,如后续准备分配新的节,则将SizeOfNewSection填入准备要加入新的节的大小
LPVOID _OpenFile(IN const LPSTR str, IN size_t SizeOfNewSection);
//读取文件标识，存储到FileSign结构中，返回节表数量
size_t _ReadData(IN LPVOID FileBuffer, OUT struct FileSign* FileSign);
//读取节表关键字段
void _ReadSectionTable(OUT struct SectionTable* pSectionTable, IN struct FileSign* pFileSign);
//输出PE结构关键字段
void _OutputPEData(IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable);
//将缓冲区的文件读取到分配的可执行可读写内存里
LPVOID _vFileBuffer(IN LPVOID FileBuffer, IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable);
//跳转至EntryPoint运行
void _Run(IN struct FileSign* pFileSign, IN LPVOID vFileBuffer);
//返回代码节数
size_t _FindCodeSection(IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable);
//将改写好的ImageBuffer重写为FileBuffer,返回NewBuffer的指针&&NewBuffer的大小
size_t _NewBuffer(IN LPVOID* vFileBuffer, IN struct SectionTable* pSectionTable, IN struct FileSign* pFileSign, IN size_t SizeOfCode, OUT LPVOID* NewBuffer);
//将NewBuffer存盘
void _SaveFile(IN LPVOID Buffer, IN LPSTR New_FilePATH);
//写入新的节
LPVOID _AddNewSection(OUT LPVOID FileBuffer, IN LPCSTR SectionName, IN size_t SizeOfSection);
//计算文件对齐，返回对齐后的大小
size_t _MemoryAlign(size_t FileSize, size_t Align);
//将节合并为一个
void _Mergesection(LPVOID vFileBuffer, struct FileSign* pFileSign, struct SectionTable* pSectionTable, LPSTR SectionName);
//将导出表挪入指定节，返回节的地址
DWORD _MoveExportByAddr(IN LPVOID FileBuffer, IN LPVOID CodeBegin_FOA);
//根据节的名字将导出表挪入节首
LPVOID _MoveExportBySection(IN LPVOID FileBuffer, IN LPCSTR SectionName);
//将重定位表挪入指定位置FOA
DWORD _MoveReloc(LPVOID FileBuffer, LPVOID CodeBegin_FOA);



//不可复用,将shellcode写入代码段结尾
void _WriteShellCodeToIdleArea(OUT LPVOID vFileBuffer, IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable, IN char* shellcode, IN size_t SizeOfCode);


//将Shellcode写入新的节
void _WriteShellCodeToNewSection(OUT LPVOID vFileBuffer, IN struct SectionTable* pSectionTable, IN struct FileSign* pFileSign, IN LPSTR ShellCode, IN size_t SizeOfShellcode);

//为最后一个节扩容
void _ExpansionSection(OUT LPVOID FileBuffer, IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable, IN size_t ExpansionSize);


//将RVA转换为FOA
DWORD _RVAToFOA(LPVOID FileBuffer, DWORD RVA);

//将FOA转换为RVA
DWORD _FOAToRVA(LPVOID FileBuffer, DWORD FOA);


//寻找当前地址所在的节
DWORD _FindRVASection(LPVOID FileBuffer, DWORD RVA, struct FileSign* pFileSign, struct SectionTable* pSectionTable);


//参数为FileBuffer，要寻找的函数的名字，返回函数在FileBuffer中的地址
LPVOID _GetFunctionAddrByName(LPVOID FileBuffer, LPSTR FunctionName);

//读取重定位表
void _PrintReloc(LPVOID FileBuffer);

//打印导入表
void _PrintImport(IN LPVOID FileBuffer);

//打印导入表_x64
void _PrintImport_x64(IN LPVOID FileBuffer);

//打印BoundImport
void _ShowBoundImport(IN LPVOID FileBuffer);
//打印BoundImport_x64
void _ShowBoundImport_x64(LPVOID FileBuffer);



//PE，可选PE头
struct FileSign {
	//定位指针
	LPVOID NTHeader;
	LPVOID PEHeader;
	LPVOID OptionalHeader;

	//PE头
	DWORD MZHeader;
	WORD Machine;
	WORD NumberOfSection;
	DWORD SizeOfOptionHeader;

	//可选PE头
	WORD Magic;
	DWORD EntryPoint;
	DWORD ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
};


//节表
struct SectionTable {
	LPVOID Point;
	char name[9];
	DWORD VirtualSize;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointToRawData;
	DWORD Characteristics;
};



