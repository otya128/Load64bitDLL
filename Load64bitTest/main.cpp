#include <stdio.h>
#include "Load64bitDll.h"

int main(void)
{
    auto user32 = LoadLibraryW64(L"user32.dll");
    auto messagebox = GetProcAddress64(user32, "MessageBoxW");
    Call64<int>(messagebox, NULL, L"hello", L"hello", MB_OK);
    return 0;
}
