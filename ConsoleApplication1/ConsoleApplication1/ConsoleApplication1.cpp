// ConsoleApplication1.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#include <iostream>
#include <string>
#include "Task.h"
//A

int main()
{
    std::cout << "Hello World!\n";
    LPCWSTR nameCont = L"Alex";
    printTypes();
    int type = cin("Choose type: ");
    LPTSTR nameProv = printAndGetProviders(type);
    HCRYPTPROV hCrProv = getProvider(nameProv, type, nameCont);
    HCRYPTPROV hCrProvSession = 0;
    ALG_ID alg_id = printAlgosProv(hCrProv);
    
    
    //Task4(hCrProv, nameProv, type, nameCont);
    HCRYPTKEY kSign = genKeySign(hCrProv, nameProv, type);
    HCRYPTKEY kSession = genKeySession(hCrProv, nameProv, type, alg_id);
    HCRYPTKEY kProtectedPub = ImportKey("C:\\KeyPubAssymetric.key", false, hCrProv); //exchange B

    printf("Imported key B:\n");
    DWORD lenBlobImport = 0;
    BYTE* blobImport = getBlob(lenBlobImport, kProtectedPub, 0, PUBLICKEYBLOB);
    printBlob(blobImport, lenBlobImport);
    
    printf("Exported session key A:\n");
    ExportKey(kSession, kProtectedPub, "C:\\KeySession.enc", SIMPLEBLOB);
    
    printf("Exported sign key A:\n");
    ExportKey(kSign, 0, "C:\\KeySign.enc", PUBLICKEYBLOB);
    //Task5(hCrProv, nameProv, type, nameCont);
    DWORD blobMessageLen = 0;
   
    BYTE* blobMessage = strToBlob(cins("Enter message: "), blobMessageLen);
    HCRYPTHASH hCryptHash = CreateHash(hCrProv);
    //addToHashData(hCryptHash, blobMessage, blobMessageLen);
    DWORD encMessageLen = blobMessageLen;
    BYTE* encMessage;
    encrypt(kSession, hCryptHash, blobMessage, &encMessage, encMessageLen);
    
    BYTE* signData = 0;
    DWORD signDataLen = 0;
    SignHash(hCryptHash, &signData, signDataLen);
    

    WriteBlobToFile(encMessage, encMessageLen, "C:\\EncMessage.bin");
    WriteBlobToFile(signData, signDataLen, "C:\\SignMessage.bin");
    
    //decrypt(kSession, 0, encMessage, encMessageLen);
    std::cout << std::boolalpha;
    std::cout << "Destroy sign key: " << (bool)CryptDestroyKey(kSign) << std::endl;
    std::cout << "Destroy session key: " << (bool)CryptDestroyKey(kSession) << std::endl;
    std::cout << "Destroy export exchange key: " << (bool)CryptDestroyKey(kProtectedPub) << std::endl;
    std::cout << "Destroy hash obj: " << (bool)CryptDestroyHash(hCryptHash) << std::endl;
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
