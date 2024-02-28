#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#include <iostream>
#include <string>
#include "Tasks.h"

int main()
{
    std::cout << "Hello World!\n";
    printTypes();
    int type = cin("Choose type: ");
    LPTSTR nameProv = printAndGetProviders(type);
    HCRYPTPROV hCrProv = getProvider(nameProv, type);
    ALG_ID alg_id = printAlgosProv(hCrProv);

    LPCWSTR nameCont = L"Alex";
    HCRYPTKEY kExchange = genKeyExchange(hCrProv, nameProv, type, nameCont);
    
    printf("Exported key B:\n");
    ExportKey(kExchange, NULL, "C:\\KeyPubAssymetric.key", PUBLICKEYBLOB);
    //Task5(hCrProv, nameProv, type, nameCont);

    std::string str;
    std::cout << "Wait command to get sign key...";
    std::cin >> str;

    printf("Imported sign key A:\n");
    HCRYPTKEY kSign = ImportKey("C:\\KeySign.enc", false, hCrProv);
    DWORD lenBlobImport = 0;
    BYTE* blobImport = getBlob(lenBlobImport, kSign, 0, PUBLICKEYBLOB);
    printBlob(blobImport, lenBlobImport);
    
    std::cout << std::boolalpha;
    std::cout << "Destroy sign key: " << (bool)CryptDestroyKey(kSign) << std::endl;
    std::cout << "Destroy exchange key: " << (bool)CryptDestroyKey(kExchange) << std::endl;
    

    LocalFree(nameProv);
    return 0;
}

// Запуск программы: CTRL+F5 или меню "Отладка" > "Запуск без отладки"
// Отладка программы: F5 или меню "Отладка" > "Запустить отладку"

// Советы по началу работы 
//   1. В окне обозревателя решений можно добавлять файлы и управлять ими.
//   2. В окне Team Explorer можно подключиться к системе управления версиями.
//   3. В окне "Выходные данные" можно просматривать выходные данные сборки и другие сообщения.
//   4. В окне "Список ошибок" можно просматривать ошибки.
//   5. Последовательно выберите пункты меню "Проект" > "Добавить новый элемент", чтобы создать файлы кода, или "Проект" > "Добавить существующий элемент", чтобы добавить в проект существующие файлы кода.
//   6. Чтобы снова открыть этот проект позже, выберите пункты меню "Файл" > "Открыть" > "Проект" и выберите SLN-файл.
