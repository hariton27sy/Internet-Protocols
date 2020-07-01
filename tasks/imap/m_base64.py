BASE64_LINE = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
EQ_ORD = ord('=')


def encode(data: (bytes, str)):
    if isinstance(data, str):
        data = data.encode('utf8')
    result = bytearray()
    for i in range(0, len(data), 3):
        delta = min(3, len(data) - i)
        number = bin(int.from_bytes(data[i:i + 3], 'big'))[2:].zfill(8 * delta).ljust(6 * (delta + 1), '0')
        for j in range(0, len(number), 6):
            result.append(BASE64_LINE[int(number[j:j+6], 2)])
        result.extend(b'=' * (3 - delta))

    return bytes(result)


def decode(data: bytes):
    result = bytearray()
    for i in range(0, len(data), 4):
        eq_count = (data[i + 3] == EQ_ORD) + (data[i + 2] == EQ_ORD)
        temp = ''.join(map(lambda x: bin(BASE64_LINE.find(x))[2:].zfill(6), data[i:i + 4].rstrip(b'=')))
        for j in range(0, 8 * (3 - eq_count), 8):
            result.append(int(temp[j:j+8], 2))
    return bytes(result)


if __name__ == "__main__":
    enc = encode(b'\0hariton27sy@yandex.ru\0jelly0912200')
    print(enc)
    print(decode(enc))
