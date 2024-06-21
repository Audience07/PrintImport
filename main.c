#include "head.h"


LPSTR PATH = "QQ.exe";

int main() {
	LPVOID FileBuffer = _OpenFile(PATH, 0);
	if (!FileBuffer) {
		printf("[-]打开文件失败\n");
		return 0;
	}
	_PrintImport_x64(FileBuffer);
	/*_ShowBoundImport_x64(FileBuffer);*/
	

}