#include <Windows.h>
#include <bcrypt.h>

#include <string>
#include <vector>
#include <tuple>
#include <memory>
//*************************************************************************************************
const int aes_block_length = 16;
//*************************************************************************************************
std::tuple<int, int, int> checkLen(int len)
{
    const int padSize = aes_block_length - (len % aes_block_length);
    const int maxLength = len + padSize;

    return {
        len >= aes_block_length,
        padSize,
        maxLength
    };
}
//*************************************************************************************************
std::vector<unsigned char> NFold(std::vector<unsigned char>& buffer, size_t size)
{
    auto inBytesSize = buffer.size();

    auto a = size;
    auto b = inBytesSize;

    while(b != 0)
    {
        auto c = b;
        b = a % b;
        a = c;
    }

    auto lcm = (size * inBytesSize) / a;

    std::vector<unsigned char> result;
    result.resize(size);

    unsigned int tmpByte = 0;

    for(long long i = (lcm - 1); i >= 0; i--)
    {
        unsigned int msbit = (inBytesSize << 3) - 1;
        unsigned int div = i / inBytesSize;

        msbit += ((inBytesSize << 3) + 13) * div;
        msbit += (inBytesSize - (i % inBytesSize)) << 3;
        msbit %= inBytesSize << 3;

        auto rst = buffer[(inBytesSize - 1 - (msbit >> 3)) % inBytesSize] & 0xff;
        auto rst2 = buffer[(inBytesSize - (msbit >> 3)) % inBytesSize] & 0xff;

        msbit = ((rst << 8) | (rst2)) >> ((msbit & 7) + 1) & 0xff;

        tmpByte += msbit;
        msbit = result[i % size] & 0xff;
        tmpByte += msbit;

        result[i % size] = (tmpByte & 0xff);

        tmpByte >>= 8;
    }

    if(tmpByte != 0)
    {
        for(long long i = size - 1; i >= 0; i--)
        {
            tmpByte += result[i] & 0xff;
            result[i] = (tmpByte & 0xff);

            tmpByte >>= 8;
        }
    }

    return result;
}
//*************************************************************************************************
void swapBlocks(std::vector<unsigned char>* text)
{
    auto blockOne = text->size() - (aes_block_length << 1);
    auto blockTwo = text->size() - aes_block_length;

    for(int i = 0; i < aes_block_length; i++)
    {
        auto temp = text->at(i + blockOne);

        text->at(i + blockOne) = text->at(i + blockTwo);
        text->at(i + blockTwo) = temp;
    }
}
//*************************************************************************************************
std::vector<unsigned char> aesEncrypt(std::vector<unsigned char> data, std::vector<unsigned char> key)
{
    BCRYPT_ALG_HANDLE handle;

    auto bcryptResult = BCryptOpenAlgorithmProvider(&handle, BCRYPT_AES_ALGORITHM, 0, 0);
    bcryptResult = BCryptSetProperty(handle, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    size_t InformationLength = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + key.size();

    auto Information = new unsigned char[InformationLength]();
    if(!Information)
        throw std::exception("Out of memory");

    auto InformationGuard = std::unique_ptr<unsigned char[]>{ Information };

    PBCRYPT_KEY_DATA_BLOB_HEADER header = reinterpret_cast<PBCRYPT_KEY_DATA_BLOB_HEADER>(Information);

    header->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    header->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    header->cbKeyData = key.size();

    std::copy(key.begin(), key.end(), (unsigned char*)(header + 1));

    BCRYPT_KEY_HANDLE newKey = nullptr;

    bcryptResult = BCryptImportKey(handle, nullptr, BCRYPT_KEY_DATA_BLOB, &newKey, nullptr, 0, Information, InformationLength, 0);

    auto [flag, padSize, maxLength] = checkLen(data.size());
    if(!flag)
        return data;

    std::vector<unsigned char> enc_text;

    if(padSize == aes_block_length)
        enc_text = data;
    else
    {
        enc_text.insert(enc_text.end(), data.begin(), data.end());
        enc_text.resize(data.size() + padSize);
    }

    std::vector<unsigned char> iv;
    iv.resize(aes_block_length);

    ULONG ret_size = 0;

    auto status = BCryptEncrypt(newKey, enc_text.data(), enc_text.size(), nullptr, iv.data(), iv.size(), nullptr, 0, &ret_size, 0);

    std::vector<unsigned char> encrypted;
    encrypted.resize(ret_size);

    status = BCryptEncrypt(newKey, enc_text.data(), enc_text.size(), nullptr, iv.data(), iv.size(), encrypted.data(), encrypted.size(), &ret_size, 0);

    if(encrypted.size() >= (aes_block_length << 1))
        swapBlocks(&encrypted);

    encrypted.resize(data.size());

    return encrypted;
}
//*************************************************************************************************
std::vector<unsigned char> DR(std::vector<unsigned char>& key, std::vector<unsigned char>& constant, int keySize, int blockSize)
{
    std::vector<unsigned char> keyBytes;
    keyBytes.resize(keySize);

    std::vector<unsigned char> ki;

    if(constant.size() != blockSize)
        ki = NFold(constant, blockSize);
    else
        ki = constant;

    int n = 0;

    do
    {
        ki = aesEncrypt(ki, key);

        if(n + blockSize >= keySize)
        {
            std::copy(ki.begin(), ki.begin() + (keySize - n), keyBytes.begin() + n);
            break;
        }

        std::copy(ki.begin(), ki.begin() + blockSize, keyBytes.begin() + n);

        n += blockSize;

    } while(n < keySize);

    return keyBytes;
}
//*************************************************************************************************
void aesDecrypt(std::vector<unsigned char> data, std::vector<unsigned char> key)
{
    BCRYPT_ALG_HANDLE handle;

    auto bcryptResult = BCryptOpenAlgorithmProvider(&handle, BCRYPT_AES_ALGORITHM, 0, 0);
    bcryptResult = BCryptSetProperty(handle, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    size_t InformationLength = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + key.size();

    auto Information = new unsigned char[InformationLength]();
    if(!Information)
        throw std::exception("Out of memory");

    auto InformationGuard = std::unique_ptr<unsigned char[]>{ Information };

    PBCRYPT_KEY_DATA_BLOB_HEADER header = reinterpret_cast<PBCRYPT_KEY_DATA_BLOB_HEADER>(Information);

    header->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    header->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    header->cbKeyData = key.size();

    std::copy(key.begin(), key.end(), (unsigned char*)(header + 1));

    BCRYPT_KEY_HANDLE newKey = nullptr;

    bcryptResult = BCryptImportKey(handle, nullptr, BCRYPT_KEY_DATA_BLOB, &newKey, nullptr, 0, Information, InformationLength, 0);

    auto [flag, padSize, maxLength] = checkLen(data.size());

    std::vector<unsigned char> iv;
    iv.resize(aes_block_length);

    std::vector<unsigned char> enc_text;

    if(padSize != aes_block_length)
    {
        auto offset = data.size() - (aes_block_length << 1) + padSize;
        std::vector<unsigned char> depadded{ data.begin() + offset, data.begin() + offset + aes_block_length};

        ULONG ret_size = 0;

        auto status = BCryptDecrypt(newKey, depadded.data(), depadded.size(), nullptr, iv.data(), iv.size(), nullptr, 0, &ret_size, 0);

        std::vector<unsigned char> depadded_decrypted;
        depadded_decrypted.resize(ret_size);

        status = BCryptDecrypt(newKey, depadded.data(), depadded.size(), nullptr, iv.data(), iv.size(), depadded_decrypted.data(), depadded_decrypted.size(), &ret_size, 0);

        enc_text.insert(enc_text.end(), data.begin(), data.end());
        enc_text.insert(enc_text.end(), depadded_decrypted.begin() + (depadded_decrypted.size() - padSize), depadded_decrypted.end());

        int jjj = 0;
    }

    if(enc_text.size() >= (aes_block_length << 1))
        swapBlocks(&enc_text);

    iv.clear();
    iv.resize(aes_block_length);

    ULONG ret_size = 0;

    auto status = BCryptDecrypt(newKey, enc_text.data(), enc_text.size(), nullptr, iv.data(), iv.size(), nullptr, 0, &ret_size, 0);

    std::vector<unsigned char> decrypted;
    decrypted.resize(ret_size);

    status = BCryptDecrypt(newKey, enc_text.data(), enc_text.size(), nullptr, iv.data(), iv.size(), decrypted.data(), decrypted.size(), &ret_size, 0);
}
//*************************************************************************************************
int main()
{
	return 0;
}
//*************************************************************************************************
