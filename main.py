# -*- coding: utf-8
from bitarray import bitarray
from functions import form_sequence, bitarray_to_hex_string, write_bitarray_to_file

# Проверка первого случая.
# K и S случайны.
key = bitarray(56, endian='big')
s = bitarray(64, endian='big')

result = form_sequence(key, s)

print 'Initial:'
print 'K: {0}'.format(key)
print 'S: {0}'.format(s)
print 'Result: {0}'.format(result)
print 'Hex result: {0}'.format(bitarray_to_hex_string(result))
write_bitarray_to_file(result, '1.result')

# Проверка второго случая.
# Один из битов K меняется на противоположный, S неизменна.
key[0] = not key[0]
result = form_sequence(key, s)

print 'Changed K[0]:'
print 'K: {0}'.format(key)
print 'S: {0}'.format(s)
print 'Result: {0}'.format(result)
print 'Hex result: {0}'.format(bitarray_to_hex_string(result))
write_bitarray_to_file(result, '2.result')

# Проверка треттьего случая.
# K неизменный, один из битов S менятется на противоположный.
s[0] = not s[0]
result = form_sequence(key, s)

print 'Changed S[0]:'
print 'K: {0}'.format(key)
print 'S: {0}'.format(s)
print 'Result: {0}'.format(result)
print 'Hex result: {0}'.format(bitarray_to_hex_string(result))
write_bitarray_to_file(result, '3.result')
