#pragma once
#include <tchar.h>
#include <wincrypt.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <windows.h>
#include <vector>

void printTypes();
LPTSTR printAndGetProviders(DWORD type);
void Task1();
LPTSTR Task2(DWORD type);
HCRYPTPROV Task3(LPTSTR pszName, DWORD type);
void Task4(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type, LPCWSTR nameContainer);
void Task5(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type, LPCWSTR nameContainer);

void printNamesContFromProv(HCRYPTPROV hCryptProv);
int cin(std::string str);
PROV_ENUMALGS parse(BYTE* data);
void printInfo(PROV_ENUMALGS info);
HCRYPTKEY genKeyExchange(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type);
HCRYPTKEY genKeySign(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type, LPCWSTR nameContainer);
void WriteBlobToFile(BYTE* pbData, DWORD cbData, LPCSTR FName);
BYTE* ReadBlobFile(DWORD& bufLen, LPCSTR nameFile);
void printBlob(BYTE* blob, DWORD lenBlob);
HCRYPTKEY getAsymmetricKey(HCRYPTPROV hCryptProv);
void decrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BYTE* dataIn, DWORD& lenInData);
HCRYPTHASH CreateHash(HCRYPTPROV hCryptProv);


HCRYPTKEY genKeyExchange(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type) {
    LPSTR pszUserName;
    DWORD dwUserNameLen;
    

    //?????
    if (!CryptGetProvParam(
        hCryptProv,               // Дескриптор CSP
        PP_CONTAINER,             // Получение имени ключевого контейнера
        NULL,                     // Указатель на имя ключевого контейнера
        &dwUserNameLen,           // Длина имени
        0))
    {
        // Ошибка получении имени ключевого контейнера
        printf("Error: %d", GetLastError());
        exit(1);
    }
    ////end???????

    // Лучше использовать auto_ptr:
    //std::auto_ptr<char> aptrUserName(new char[dwUserNameLen+1]);
    //szUserName = aptrUserName.get();
    pszUserName = (char*)malloc((dwUserNameLen + 1));

    if (!CryptGetProvParam(
        hCryptProv,               // Дескриптор CSP
        PP_CONTAINER,             // Получение имени ключевого контейнера
        (LPBYTE)pszUserName,      // Указатель на имя ключевого контейнера
        &dwUserNameLen,           // Длина имени
        0))
    {
        // Ошибка получении имени ключевого контейнера
        free(pszUserName);
        printf("error occurred getting the key container name. Error: %d", GetLastError());
        exit(1);
    }
    else
    {
        printf("A crypto context has been acquired and \n");
        printf("The name on the key container is %s\n\n", pszUserName);
        free(pszUserName);
    }
    HCRYPTKEY hKeyExchange = 0;
    // Контекст с ключевым контейнером доступен,
    // попытка получения дескриптора ключа подписи
    if (CryptGetUserKey(
        hCryptProv,                     // Дескриптор CSP
        AT_KEYEXCHANGE,                   // Спецификация ключа
        &hKeyExchange))                         // Дескриптор ключа
    {
        printf("A AT_KEYEXCHANGE key is available.\n");
    }
    else
    {
        printf("No AT_KEYEXCHANGE key is unavailable.\n");

        // Ошибка в том, что контейнер не содержит ключа.
        if (!(GetLastError() == (DWORD)NTE_NO_KEY)) {
            printf("An error other than NTE_NO_KEY getting signature key.\n");
            exit(1);
        }


        // Создание подписанной ключевой пары. 
        printf("The AT_KEYEXCHANGE key does not exist.\n");
        printf("Creating a AT_KEYEXCHANGE key pair...\n");

        if (!CryptGenKey(
            hCryptProv,
            AT_KEYEXCHANGE,
            CRYPT_EXPORTABLE, //flag
            &hKeyExchange))
        {
            printf("Error occurred creating a exchange key.\n");
            exit(1);
        }
        printf("Created a exchange key pair.\n");

    }

    return hKeyExchange;
}

HCRYPTKEY genKeySign(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type, LPCWSTR nameContainer) {
    LPSTR pszUserName;
    DWORD dwUserNameLen;
    if (CryptAcquireContext(
        &hCryptProv,
        nameContainer,
        pszNameProv,
        type,
        0))
    {
        printf("A exist key container has been got.\n");
    }
    else
    {
        if (!CryptAcquireContext(
            &hCryptProv,
            nameContainer,
            pszNameProv,
            type,
            CRYPT_NEWKEYSET))
        {
            printf("Could not create a new key container.\n");
            exit(1);

        }
        printf("A new key container has been created.\n");

    }

    //?????
    if (!CryptGetProvParam(
        hCryptProv,               // Дескриптор CSP
        PP_CONTAINER,             // Получение имени ключевого контейнера
        NULL,                     // Указатель на имя ключевого контейнера
        &dwUserNameLen,           // Длина имени
        0))
    {
        // Ошибка получении имени ключевого контейнера
        printf("Error: %d", GetLastError());
        exit(1);
    }
    ////end???????

    // Лучше использовать auto_ptr:
    //std::auto_ptr<char> aptrUserName(new char[dwUserNameLen+1]);
    //szUserName = aptrUserName.get();
    pszUserName = (char*)malloc((dwUserNameLen + 1));

    if (!CryptGetProvParam(
        hCryptProv,               // Дескриптор CSP
        PP_CONTAINER,             // Получение имени ключевого контейнера
        (LPBYTE)pszUserName,      // Указатель на имя ключевого контейнера
        &dwUserNameLen,           // Длина имени
        0))
    {
        // Ошибка получении имени ключевого контейнера
        free(pszUserName);
        printf("error occurred getting the key container name. Error: %d", GetLastError());
        exit(1);
    }
    else
    {
        printf("A crypto context has been acquired and \n");
        printf("The name on the key container is %s\n\n", pszUserName);
        free(pszUserName);
    }
    HCRYPTKEY hKeySign = 0;

    if (CryptGetUserKey(
        hCryptProv,                     // Дескриптор CSP
        AT_SIGNATURE,                   // Спецификация ключа
        &hKeySign))                         // Дескриптор ключа
    {
        printf("A signature key is available.\n");
    }
    else
    {
        printf("No signature key is available.\n");

        // Ошибка в том, что контейнер не содержит ключа.

        if (!(GetLastError() == (DWORD)NTE_NO_KEY)) {
            printf("An error other than NTE_NO_KEY getting signature key.\n");
            //exit(1);
        }


        // Создание подписанной ключевой пары. 
        printf("The signature key does not exist.\n");
        printf("Creating a signature key pair...\n");

        if (!CryptGenKey(
            hCryptProv,
            AT_SIGNATURE,
            CRYPT_EXPORTABLE, //flag
            &hKeySign))
        {
            printf("Error occurred creating a signature key.\n");
            exit(1);
        }
        printf("Created a signature key pair.\n");

    }



    printf("Everything is okay. A signature key\n");
    printf("pair and an exchange key exist in\n");
    wprintf(L"the %s key container.\n", nameContainer);

    return hKeySign;
}

BYTE* getBlob(DWORD &lenData, HCRYPTKEY keyExport, HCRYPTKEY keyProtected, DWORD  dwBlobType) {
    BYTE* blobData;
    
    if (!CryptExportKey(keyExport, keyProtected, dwBlobType, 0, NULL, &lenData)) {
        printf("Failed export key. Error %d\n", GetLastError());
        exit(1);
    }
    blobData = (BYTE*)malloc(lenData);

    if (!CryptExportKey(keyExport, keyProtected, dwBlobType, 0, blobData, &lenData)) {
        printf("Failed export key. Error %d\n", GetLastError());
        exit(1);
    }

    return blobData;
}

void ExportKey(HCRYPTKEY keyExport, HCRYPTKEY keyProtected, LPCSTR nameFile, DWORD  dwBlobType) {
    BYTE* blobData;
    DWORD lenData;

    blobData = getBlob(lenData, keyExport, keyProtected, dwBlobType);

    printf("Success export key.\n");
    WriteBlobToFile(blobData, lenData, nameFile);
    printBlob(blobData, lenData);


}

HCRYPTKEY genKeySession(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type, LPCWSTR nameContainer, ALG_ID alg_id) {
    LPSTR pszUserName;
    DWORD dwUserNameLen;
    if (CryptAcquireContext(
        &hCryptProv,
        nameContainer,
        pszNameProv,
        type,
        0))
    {
        printf("A exit key container has been got.\n");
    }
    else
    {
        if (!CryptAcquireContext(
            &hCryptProv,
            nameContainer,
            pszNameProv,
            type,
            CRYPT_NEWKEYSET))
        {
            printf("Could not create a new key container.\n");
            exit(1);

        }
        printf("A new key container has been created.\n");

        //return NULL;
    }

    //?????
    if (!CryptGetProvParam(
        hCryptProv,               // Дескриптор CSP
        PP_CONTAINER,             // Получение имени ключевого контейнера
        NULL,                     // Указатель на имя ключевого контейнера
        &dwUserNameLen,           // Длина имени
        0))
    {
        // Ошибка получении имени ключевого контейнера
        printf("Error: %d", GetLastError());
        exit(1);
    }
    ////end???????

    // Лучше использовать auto_ptr:
    //std::auto_ptr<char> aptrUserName(new char[dwUserNameLen+1]);
    //szUserName = aptrUserName.get();
    pszUserName = (char*)malloc((dwUserNameLen + 1));

    if (!CryptGetProvParam(
        hCryptProv,               // Дескриптор CSP
        PP_CONTAINER,             // Получение имени ключевого контейнера
        (LPBYTE)pszUserName,      // Указатель на имя ключевого контейнера
        &dwUserNameLen,           // Длина имени
        0))
    {
        // Ошибка получении имени ключевого контейнера
        free(pszUserName);
        printf("error occurred getting the key container name. Error: %d", GetLastError());
        exit(1);
    }
    else
    {
        printf("A crypto context has been acquired and \n");
        printf("The name on the key container is %s\n\n", pszUserName);
        free(pszUserName);
    }
    HCRYPTKEY hKeySession = 0;

    if (CryptGetUserKey(
        hCryptProv,                     // Дескриптор CSP
        alg_id,                   // Спецификация ключа
        &hKeySession))                         // Дескриптор ключа
    {
        printf("A simmetric key is available.\n");
    }
    else
    {
        printf("No simmetric key is available.\n");

        // Ошибка в том, что контейнер не содержит ключа.
        /*
        if (!(GetLastError() == (DWORD)NTE_NO_KEY)) {
            printf("An error other than NTE_NO_KEY getting simmetric key.\n");
            //exit(1);
        }
        */


        // Создание симметричного ключа. 
        printf("The signature key does not exist.\n");
        printf("Creating a simmetric key...\n");

        if (!CryptGenKey(
            hCryptProv,
            alg_id,
            CRYPT_EXPORTABLE, //flag
            &hKeySession))
        {
            printf("Error occurred creating a simmetric key.\n");
            exit(1);
        }
        printf("Created a simmetric key.\n");

    }




    wprintf(L"the %s simmetric key container.\n", nameContainer);

    return hKeySession;
}

void WriteBlobToFile(BYTE* pbData, DWORD cbData, LPCSTR FName)
{
    FILE* file;

    // Открытие файла на запись в него BLOB-а
    if (!(fopen_s(&file, FName, "wb")))
    {
        printf("The file '%s' was opened\n", FName);
    }
    else
    {
        fclose(file);
        printf("Problem opening the file\n");
        exit(1);
    }

    // Запись BLOB-а в файл
    if (fwrite(pbData, 1, cbData, file))
    {
        printf("The blob was written to the '%s'\n", FName);
    }
    else
    {
        fclose(file);
        printf("The blob can not be written to file.");
        exit(1);
    }

    fclose(file);
}


BYTE* ReadBlobFile(DWORD& bufLen, LPCSTR nameFile) {
    BYTE* pbKeyBlobExport = NULL;
    FILE* EncryptedKeyBlob = NULL;
    //Открытие Файла блоба зашифрованного закрытого Ключа
    if ((fopen_s(&EncryptedKeyBlob, nameFile, "r+b"))) {
        printf("Problem opening the file '%s'\n", nameFile);
        exit(1);
    }


    printf("The file '%s' was opened\n", nameFile);

    //------------------------------------------------------------------
    // получение зашифрованного закрытого Ключа
    //------------------------------------------------------------------
    // находим размер файла EncryptedKeyBlob.enc, записываем его в szfile
    fseek(EncryptedKeyBlob, 0, SEEK_END);
    DWORD szf = ftell(EncryptedKeyBlob);
    fseek(EncryptedKeyBlob, 0, SEEK_SET);

    // выделение памяти
    pbKeyBlobExport = (BYTE*)malloc(szf);
    if (!pbKeyBlobExport) {
        fclose(EncryptedKeyBlob);
        printf("Out of memory.");
        exit(1);
    }


    // чтение зашифрованного закрытого Ключа из файла EncryptedKeyBlob.enc 
    DWORD dwKeyBlobExportLen = (DWORD)fread(pbKeyBlobExport, 1, szf, EncryptedKeyBlob);
    if (!dwKeyBlobExportLen) {
        fclose(EncryptedKeyBlob);
        printf("The private Key can not be reading from the 'EncryptedKeyBlob.enc'\n");
        exit(1);
    }

    printf("The private Key was read from the 'EncryptedKeyBlob.enc'\n");
    fclose(EncryptedKeyBlob);
    bufLen = dwKeyBlobExportLen;
    return pbKeyBlobExport;
}

void Task1(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type, LPCWSTR nameContainer) {
    LPSTR pszUserName;
    DWORD dwUserNameLen;
    if (CryptAcquireContext(
        &hCryptProv,
        nameContainer,
        pszNameProv,
        type,
        CRYPT_NEWKEYSET))
    {
        printf("A new key container has been created.\n");
    }
    else
    {
        printf("Could not create a new key container.\n");
        return;
    }

    //?????
    if (!CryptGetProvParam(
        hCryptProv,               // Дескриптор CSP
        PP_CONTAINER,             // Получение имени ключевого контейнера
        NULL,                     // Указатель на имя ключевого контейнера
        &dwUserNameLen,           // Длина имени
        0))
    {
        // Ошибка получении имени ключевого контейнера
        printf("Error: %d", GetLastError());
        exit(1);
    }
    ////end???????

    // Лучше использовать auto_ptr:
    //std::auto_ptr<char> aptrUserName(new char[dwUserNameLen+1]);
    //szUserName = aptrUserName.get();
    pszUserName = (char*)malloc((dwUserNameLen + 1));

    if (!CryptGetProvParam(
        hCryptProv,               // Дескриптор CSP
        PP_CONTAINER,             // Получение имени ключевого контейнера
        (LPBYTE)pszUserName,      // Указатель на имя ключевого контейнера
        &dwUserNameLen,           // Длина имени
        0))
    {
        // Ошибка получении имени ключевого контейнера
        free(pszUserName);
        printf("error occurred getting the key container name. Error: %d", GetLastError());
        exit(1);
    }
    else
    {
        printf("A crypto context has been acquired and \n");
        printf("The name on the key container is %s\n\n", pszUserName);
        free(pszUserName);
    }
    HCRYPTKEY hKeyExchange = 0;
    // Контекст с ключевым контейнером доступен,
    // попытка получения дескриптора ключа подписи
    if (CryptGetUserKey(
        hCryptProv,                     // Дескриптор CSP
        AT_KEYEXCHANGE,                   // Спецификация ключа
        &hKeyExchange))                         // Дескриптор ключа
    {
        printf("A signature key is available.\n");
    }
    else
    {
        printf("No signature key is available.\n");

        // Ошибка в том, что контейнер не содержит ключа.
        if (!(GetLastError() == (DWORD)NTE_NO_KEY)) {
            printf("An error other than NTE_NO_KEY getting signature key.\n");
            exit(1);
        }


        // Создание подписанной ключевой пары. 
        printf("The signature key does not exist.\n");
        printf("Creating a signature key pair...\n");

        if (!CryptGenKey(
            hCryptProv,
            AT_KEYEXCHANGE,
            0, //flag
            &hKeyExchange))
        {
            printf("Error occurred creating a exchange key.\n");
            exit(1);
        }
        printf("Created a exchange key pair.\n");

    }

    HCRYPTKEY hKeySign = 0;

    if (CryptGetUserKey(
        hCryptProv,                     // Дескриптор CSP
        AT_SIGNATURE,                   // Спецификация ключа
        &hKeySign))                         // Дескриптор ключа
    {
        printf("A signature key is available.\n");
    }
    else
    {
        printf("No signature key is available.\n");

        // Ошибка в том, что контейнер не содержит ключа.
        if (!(GetLastError() == (DWORD)NTE_NO_KEY)) {
            printf("An error other than NTE_NO_KEY getting signature key.\n");
            exit(1);
        }


        // Создание подписанной ключевой пары. 
        printf("The signature key does not exist.\n");
        printf("Creating a signature key pair...\n");

        if (!CryptGenKey(
            hCryptProv,
            AT_SIGNATURE,
            0, //flag
            &hKeySign))
        {
            printf("Error occurred creating a signature key.\n");
            exit(1);
        }
        printf("Created a signature key pair.\n");

    }



    printf("Everything is okay. A signature key\n");
    printf("pair and an exchange key exist in\n");
    wprintf(L"the %s key container.\n", nameContainer);
}


void printTypes() {
    std::cout << "\n-----Task 1-----" << std::endl;
    printf("Listing Available Provider Types:\n");

    DWORD dwIndex = 0;
    DWORD dwType;
    DWORD cbName;
    LPTSTR pszName;

    while (CryptEnumProviderTypes(dwIndex, NULL, 0, &dwType, NULL, &cbName))
    {
        if (!cbName) break;
        if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) return;
        if (!CryptEnumProviderTypes(dwIndex++, NULL, 0, &dwType, pszName, &cbName))
        {
            std::cout << "CryptEnumProvidersTypes" << std::endl;
            return;
        }

        std::wstring pszNameWSTR(pszName);
        std::string pszNameStr(pszNameWSTR.begin(), pszNameWSTR.end());

        std::cout << "--------------------------------" << std::endl;
        std::cout << "Provider name: " << pszNameStr << std::endl;
        std::cout << "Provider type: " << dwType << std::endl;
        LocalFree(pszName);
    }
}

LPTSTR printAndGetProviders(DWORD type) {
    std::cout << "\n-----Task 2-----" << std::endl;
    printf("Listing Available Providers:\n");
    DWORD dwIndex = 0;
    DWORD dwType;
    DWORD cbName;
    LPTSTR pszName;
    LPTSTR pszNameOut;

    int i = 1;
    std::vector<LPTSTR> listNamesProviders;
    while (CryptEnumProviders(dwIndex, NULL, 0, &dwType, NULL, &cbName))
    {
        if (dwType != type) {
            ++dwIndex;
            continue;
        }
        if (!cbName) break;
        if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) return NULL;
        if (!(pszNameOut = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) return NULL;

        if (!CryptEnumProviders(dwIndex++, NULL, 0, &dwType, pszName, &cbName))
        {
            std::cout << "CryptEnumProviders" << std::endl;
            return NULL;
        }
        lstrcpy(pszNameOut, pszName);

        std::wstring pszNameWSTR(pszName);
        std::string pszNameStr(pszNameWSTR.begin(), pszNameWSTR.end());
        listNamesProviders.push_back(pszNameOut);

        std::cout << "----------------" << i++ << "----------------" << std::endl;
        std::cout << "Provider name: " << pszNameStr << std::endl;
        std::cout << "Provider type: " << dwType << std::endl;
        LocalFree(pszName);
    }

    i = cin("Choose provider name: ");
    for (int a = 0; a < listNamesProviders.size(); a++) {
        if (i - 1 == a) {
            continue;
        }
        LocalFree(listNamesProviders[a]);
    }

    return listNamesProviders[i - 1];
}

HCRYPTPROV getProvider(LPTSTR pszName, DWORD type, LPCWSTR nameContainer) {

    HCRYPTPROV hCryptProv;
    BYTE       pbData[1000];       // 1000 will hold the longest 
                                   // key container name.
    if (CryptAcquireContext(&hCryptProv, nameContainer, pszName, type, 0)) {
        printf("Context has been poluchen\n");

    }
    else {
        if (CryptAcquireContext(
            &hCryptProv,
            nameContainer,
            pszName,
            type,
            CRYPT_NEWKEYSET))
        {
            printf("A new key container has been created.\n");
        }
        else
        {
            printf("Could not create a new key container.\n");
            exit(1);
        }
    }

    DWORD cbData;

    cbData = 1000;
    if (CryptGetProvParam(
        hCryptProv,
        PP_NAME,
        pbData,
        &cbData,
        0))
    {
        //printf("CryptGetProvParam succeeded.\n");
        printf("Provider name: %s\n", pbData);
    }
    else
    {
        printf("Error reading CSP name. \n");
        exit(1);
    }

    cbData = 1000;
    if (CryptGetProvParam(
        hCryptProv,
        PP_UNIQUE_CONTAINER,
        pbData,
        &cbData,
        0))
    {
        //printf("CryptGetProvParam succeeded.\n");
        printf("Uniqe name of container: %s\n", pbData);
    }
    else
    {
        printf("Error reading CSP admin pin. \n");
        exit(1);
    }

    return hCryptProv;
}

ALG_ID printAlgosProv(HCRYPTPROV hCryptProv) {
    BYTE       pbData[1000];
    DWORD cbData = 1000;
    int i = 1;
    std::vector<ALG_ID> algos;
    if (CryptGetProvParam(
        hCryptProv,
        PP_ENUMALGS,
        pbData,
        &cbData,
        CRYPT_FIRST))
    {
        std::cout << i++;
        PROV_ENUMALGS info_algo = parse(pbData);
        algos.push_back(info_algo.aiAlgid);
        printInfo(info_algo);
    }
    else
    {
        printf("Error reading CSP admin pin. \n");
        exit(1);
    }



    while (CryptGetProvParam(
        hCryptProv,
        PP_ENUMALGS,
        pbData,
        &cbData,
        CRYPT_NEXT))
    {
        std::cout << i++;
        PROV_ENUMALGS info_algo = parse(pbData);
        algos.push_back(info_algo.aiAlgid);
        printInfo(info_algo);
    }

    printf("Choose algo simmetric: ");
    std::cin >> i;

    return algos[i - 1];
}

void Task4(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type, LPCWSTR nameContainer) {  // handle for a cryptographic
                                     // provider context
    LPSTR pszUserName;
    DWORD dwUserNameLen;
    if (CryptAcquireContext(
        &hCryptProv,
        nameContainer,
        pszNameProv,
        type,
        CRYPT_NEWKEYSET))
    {
        printf("A new key container has been created.\n");
    }
    else
    {
        printf("Could not create a new key container.\n");
        return;
    }

    //?????
    if (!CryptGetProvParam(
        hCryptProv,               // Дескриптор CSP
        PP_CONTAINER,             // Получение имени ключевого контейнера
        NULL,                     // Указатель на имя ключевого контейнера
        &dwUserNameLen,           // Длина имени
        0))
    {
        // Ошибка получении имени ключевого контейнера
        printf("Error: %d", GetLastError());
        exit(1);
    }
    ////end???????

    // Лучше использовать auto_ptr:
    //std::auto_ptr<char> aptrUserName(new char[dwUserNameLen+1]);
    //szUserName = aptrUserName.get();
    pszUserName = (char*)malloc((dwUserNameLen + 1));

    if (!CryptGetProvParam(
        hCryptProv,               // Дескриптор CSP
        PP_CONTAINER,             // Получение имени ключевого контейнера
        (LPBYTE)pszUserName,      // Указатель на имя ключевого контейнера
        &dwUserNameLen,           // Длина имени
        0))
    {
        // Ошибка получении имени ключевого контейнера
        free(pszUserName);
        printf("error occurred getting the key container name. Error: %d", GetLastError());
        exit(1);
    }
    else
    {
        printf("A crypto context has been acquired and \n");
        printf("The name on the key container is %s\n\n", pszUserName);
        free(pszUserName);
    }
    HCRYPTKEY hKey = 0;
    // Контекст с ключевым контейнером доступен,
    // попытка получения дескриптора ключа подписи
    if (CryptGetUserKey(
        hCryptProv,                     // Дескриптор CSP
        AT_SIGNATURE,                   // Спецификация ключа
        &hKey))                         // Дескриптор ключа
    {
        printf("A signature key is available.\n");
    }
    else
    {
        printf("No signature key is available.\n");

        // Ошибка в том, что контейнер не содержит ключа.
        if (!(GetLastError() == (DWORD)NTE_NO_KEY)) {
            printf("An error other than NTE_NO_KEY getting signature key.\n");
            exit(1);
        }


        // Создание подписанной ключевой пары. 
        printf("The signature key does not exist.\n");
        printf("Creating a signature key pair...\n");

        if (!CryptGenKey(
            hCryptProv,
            AT_SIGNATURE,
            0,
            &hKey))
        {
            printf("Error occurred creating a signature key.\n");
            exit(1);
        }
        printf("Created a signature key pair.\n");

    }

    // Получение ключа обмена: AT_KEYEXCHANGE
    if (CryptGetUserKey(
        hCryptProv,
        AT_KEYEXCHANGE,
        &hKey))
    {
        printf("An exchange key exists. \n");
    }
    else
    {
        printf("No exchange key is available.\n");
    }



    printf("Everything is okay. A signature key\n");
    printf("pair and an exchange key exist in\n");
    wprintf(L"the %s key container.\n", nameContainer);


}

HCRYPTKEY ImportKey(LPCSTR nameFileKey, bool useProtectedKey, HCRYPTPROV hCryptProv) {
    BYTE* blobKey = 0;
    HCRYPTKEY kProtected = 0;
    HCRYPTKEY kImport = 0;
    if (useProtectedKey) {
        kProtected = getAsymmetricKey(hCryptProv);
    }

    DWORD dataLen = 0;
    blobKey = ReadBlobFile(dataLen, nameFileKey);

    if (!CryptImportKey(hCryptProv, blobKey, dataLen, kProtected, CRYPT_EXPORTABLE, &kImport)) {
        printf("Error import key. Code: %d\n", GetLastError());
        return kImport;
    }

    return kImport;
}

HCRYPTHASH CreateHash(HCRYPTPROV hCryptProv) {
    HCRYPTHASH hHash;
    if (CryptCreateHash(
        hCryptProv,
        CALG_SHA1,
        0,
        0,
        &hHash))
    {
        printf("An empty hash object has been created. \n");
    }
    else
    {
        printf("Error during CryptBeginHash!\n");
        exit(1);
    }



    return hHash;

}

bool verifySign(HCRYPTHASH hHash, BYTE* signData, DWORD signLen, HCRYPTKEY hKey) {
    if (CryptVerifySignature(hHash, signData, signLen, hKey, 0, 0)) {
        return true;
    }
    else if (GetLastError() == NTE_BAD_SIGNATURE) {
        return false;
    }
    printf("Failed signature! Uncknown error!\n");
    return false;
}

void decrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BYTE* dataIn, DWORD& lenInData) {
    if (CryptDecrypt(hKey, hHash, true, 0, dataIn, &lenInData)) {
        printf("Decryption successfull!\n");
        return;
    }
    printf("Decryption unsuccessfull!\n");
    return;
}



HCRYPTKEY getAsymmetricKey(HCRYPTPROV hCryptProv) {
    HCRYPTKEY out = 0;
    if (!CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &out)) {
        printf("Error get key. Code: %d\n", GetLastError());
        return NULL;
    }
    printf("Success get key.\n");

    return out;
}

void Task5(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type, LPCWSTR nameContainer) {  // handle for a cryptographic
                                     // provider context


    if (CryptAcquireContext(
        &hCryptProv,
        nameContainer,
        pszNameProv,
        type,
        CRYPT_DELETEKEYSET))
    {
        wprintf(L"A exist key container {%s} has been deleted.\n", nameContainer);
    }
    else
    {
        printf("Could not delete a exist key container.\n");
        exit(1);
    }
}

void printNamesContFromProv(HCRYPTPROV hCryptProv) {
    //BYTE       pbData[1000];       // 1000 will hold the longest 
                                   // key container name.
    DWORD dwFlags = CRYPT_FIRST;
    DWORD cbData;

    cbData = 1000;
    CryptGetProvParam(hCryptProv, PP_ENUMCONTAINERS, NULL, &cbData, dwFlags);
    PBYTE pbData = new BYTE[cbData];
    if (CryptGetProvParam(
        hCryptProv,
        PP_ENUMCONTAINERS,
        pbData,
        &cbData,
        dwFlags))
    {
        //printf("CryptGetProvParam succeeded.\n");
        printf("Name container: %s\n", pbData);
    }
    else
    {
        printf("ERROR_INVALID_HANDLE %d\n", ERROR_INVALID_HANDLE);
        printf("ERROR_INVALID_PARAMETER %d\n", ERROR_INVALID_PARAMETER);
        printf("ERROR_MORE_DATA %d\n", ERROR_MORE_DATA);
        printf("ERROR_NO_MORE_ITEMS %d\n", ERROR_NO_MORE_ITEMS);
        printf("NTE_BAD_FLAGS %d\n", NTE_BAD_FLAGS);
        printf("NTE_BAD_TYPE %d\n", NTE_BAD_TYPE);
        printf("NTE_BAD_UID %d\n", NTE_BAD_UID);
        printf("Error %d\n", GetLastError());
        printf("Error reading CSP name. \n");
        //exit(1);
    }

    cbData = 1000;
    while (CryptGetProvParam(
        hCryptProv,
        PP_ENUMCONTAINERS,
        pbData,
        &cbData,
        CRYPT_NEXT))
    {
        //printf("CryptGetProvParam succeeded.\n");
        printf("Name container next: %s\n", pbData);
    }

}


int cin(std::string str) {
    std::cout << str;
    int type = 1;
    std::cin >> type;

    return type;
}

PROV_ENUMALGS parse(BYTE* data) {
    PROV_ENUMALGS out;
    ALG_ID id;
    id = *(ALG_ID*)data;
    BYTE* ptr = &data[0];

    ptr += sizeof(ALG_ID);

    //id = data[0] | 8 << data[1] | 16 << data[2] | 24 << data[3];
    out.aiAlgid = id;
    out.dwBitLen = *(DWORD*)ptr;
    ptr += sizeof(DWORD);
    out.dwNameLen = *(DWORD*)ptr;
    ptr += sizeof(DWORD);
    /*
    while (!(*ptr)) {
        ++ptr;
    }
    */
    strncpy_s(out.szName, sizeof(out.szName), (char*)ptr, out.dwNameLen);
    //CHAR* szName = new CHAR[out.dwNameLen]{0};
    /*
    for (int i = 0; i < out.dwNameLen - 1; i++) {
        out.szName[i] = *ptr;

        ++ptr;
    }
    out.szName[out.dwNameLen - 1] = 0;
    */

    return out;
}

void printInfo(PROV_ENUMALGS info) {
    printf("---------------------\n");
    printf("algo_id: %d\nlen key: %d\nlen name: %d\nname algo: %s\n",
        info.aiAlgid, info.dwBitLen, info.dwNameLen, info.szName);
    printf("---------------------\n");
}

void printBlob(BYTE* blob, DWORD lenBlob) {
    BYTE* ptr = blob;
    BYTE* ptrEnd = blob + lenBlob;

    while (ptr != ptrEnd) {
        printf("%d ", * ptr);
        ++ptr;
    }
    std::cout << std::endl;
}

void printBlobStr(BYTE* blob, DWORD lenBlob) {
    BYTE* ptr = blob;
    BYTE* ptrEnd = blob + lenBlob;

    while (ptr != ptrEnd) {
        std::cout << *ptr;
        ++ptr;
    }
    std::cout << std::endl;
}