# -*- coding: utf-8
from bitarray import bitarray
import DES

bitarray_tp_hex_table = [
    '0',
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    'A',
    'B',
    'C',
    'D',
    'E',
    'F',
]


def bitarray_to_hex_string(array):
    result = ""
    for i in xrange(0, len(array), 4):
        result += bitarray_tp_hex_table[DES.Encryptor.bitarray_to_int(array[i:i + 4])]
    return result


def form_sequence(key, s):
    encryptor1 = DES.Encryptor(key, variant=1, cycles_count=16)

    # Второй этап.
    d = bitarray(64, endian='big')

    # Третий этап.
    i = encryptor1.encrypt(d)

    # Четвертый этап.
    result = bitarray(1024, endian='big')
    result.setall(False)

    for iteration in xrange(1024):
        r = i ^ s
        x = encryptor1.encrypt(r)
        t = x ^ i
        s = encryptor1.encrypt(t)
        result[iteration] = x[0]

    return result


def write_bitarray_to_file(array, filename):
    with open(filename, 'wb') as file:
        file.write(array.tobytes())
