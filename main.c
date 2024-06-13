#include "head.h"


LPSTR PATH = "C32Asm.exe";

int main() {
	LPVOID FileBuffer = _OpenFile(PATH, 0);
	_PrintImport(FileBuffer);
	

}