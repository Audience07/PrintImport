#include "head.h"


LPSTR PATH = "QQ.exe";

int main() {
	LPVOID FileBuffer = _OpenFile(PATH, 0);
	if (!FileBuffer) {
		printf("[-]���ļ�ʧ��\n");
		return 0;
	}
	_PrintImport_x64(FileBuffer);
	/*_ShowBoundImport_x64(FileBuffer);*/
	

}