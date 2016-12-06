# -*- coding: utf-8

from bitarray import bitarray
import tables


class Encryptor(object):
    def __init__(self, key, variant=1, cycles_count=1):
        self._key = key
        self._generate_keys()
        self._variant = variant
        self._cycles_count = cycles_count
        self._form_big_table()

    def encrypt(self, block):
        if not isinstance(block, bitarray):
            raise TypeError()
        if len(block) != 64:
            raise IndexError()

        # print("Before initial permutation: {0}".format(block))
        after_first_permutation = self._do_initial_permutation(block)
        # print("After initial permutation: {0}".format(after_first_permutation))
        after_feistel = self._do_cypher_cycles(after_first_permutation)
        # print("After feistel cycles: {0}".format(after_feistel))
        result = self._do_final_permutation(after_feistel)
        # print("Result: {0}".format(result))


        reverted_after_feistel = self._do_decypher_cycles(after_feistel)

        return result

    def decrypt(self, block):
        if not isinstance(block, bitarray):
            raise TypeError()
        if len(block) != 64:
            raise IndexError()

        after_last_permutation = self._do_initial_permutation(block)
        after_decypher = self._do_decypher_cycles(after_last_permutation)
        return self._do_final_permutation(after_decypher)

    def _generate_keys(self):
        self._expand_key()

        self._keys = [None] * 16

        c = [None] * 17
        d = [None] * 17

        permutation_for_c0 = tables.PERMUTATION_FOR_EXTENDED_KEY['c0']
        permutation_for_d0 = tables.PERMUTATION_FOR_EXTENDED_KEY['d0']
        self._permutation_for_expanded_key = permutation_for_c0 + permutation_for_d0

        permutated_key = self._do_permutation_for_expanded_key()
        c[0] = permutated_key[:28]
        d[0] = permutated_key[28:]

        for i in xrange(1, 17):
            c[i] = Encryptor.cyclic_shift(c[i - 1], 'left', tables.COUNTS_OF_SHIFTS[i - 1])
            d[i] = Encryptor.cyclic_shift(d[i - 1], 'left', tables.COUNTS_OF_SHIFTS[i - 1])
            self._keys[i - 1] = self._do_permutation_for_ki(c[i] + d[i])

        return

    def _expand_key(self):
        key_bytes = [None] * 8

        self._expanded_key = bitarray(endian='big')
        for i in xrange(0, 8):
            start_pos = i * 7
            key_bytes[i] = self._key[start_pos: start_pos + 7]
            if key_bytes[i].count(True) % 2 == 0:
                key_bytes[i].append(True)
            else:
                key_bytes[i].append(False)
            self._expanded_key += key_bytes[i]

    def _do_permutation_for_expanded_key(self):
        result = bitarray(56, endian='big')
        for i in xrange(0, 56):
            result[i] = self._expanded_key[self._permutation_for_expanded_key[i] - 1]
        return result

    def _do_permutation_for_ki(self, raw_ki):
        result = bitarray(48, endian='big')
        for i in xrange(0, 48):
            result[i] = raw_ki[tables.PERMUTATION_FOR_Ki[i] - 1]
        return result

    def _do_initial_permutation(self, block):
        result = bitarray(64, endian='big')
        result.setall(False)
        for i in xrange(0, 64):
            result[i] = block[tables.INITIAL_PERMUTATION[i] - 1]
        return result

    def _do_cypher_cycles(self, block):
        l = [None] * (self._cycles_count + 1)
        r = [None] * (self._cycles_count + 1)
        t = [None] * (self._cycles_count + 1)

        l[0] = block[0:32]
        r[0] = block[32:64]
        t[0] = l[0] + r[0]

        for i in xrange(1, self._cycles_count + 1):
            l[i] = r[i - 1].copy()
            r[i] = l[i - 1] ^ self._cypher_function(r[i - 1], self._keys[i - 1]  # СДЕЛАТЬ ГЕНЕРАЦИЮ КЛЮЧЕЙ
                                                    )
            t[i] = l[i] + r[i]

        return t[len(t) - 1]

    def _do_decypher_cycles(self, block):
        l = [None] * (self._cycles_count + 1)
        r = [None] * (self._cycles_count + 1)
        t = [None] * (self._cycles_count + 1)

        l[self._cycles_count] = block[:32]
        r[self._cycles_count] = block[32:]
        t[self._cycles_count] = l[self._cycles_count] + r[self._cycles_count]

        for i in xrange(self._cycles_count, 0, -1):
            r[i - 1] = l[i].copy()
            l[i - 1] = r[i] ^ self._cypher_function(l[i], self._keys[i - 1])

        return l[0] + r[0]

    def _cypher_function(self, r, k):
        after_expansion = self._expand_vector(r)
        after_expansion = after_expansion ^ k

        blocks = [None] * 8
        for i in xrange(0, 8):
            start_index = i * 6
            blocks[i] = after_expansion[start_index:start_index + 6]

        if self._variant == 1:
            transformed_r = bitarray()
            transformed_blocks = [None] * 8
            for i in xrange(0, 8):
                transformed_blocks[i] = self._block6to4(blocks[i], i)
                transformed_r += transformed_blocks[i]
        elif self._variant == 2:
            transformed_r = bitarray()
            transformed_blocks = [None] * 4
            for i in xrange(0, 4):
                ind = i * 2
                transformed_blocks[i] = self._block12to8(blocks[ind], blocks[ind + 1], i)
                transformed_r += transformed_blocks[i]

        result = self._do_permutation_p(transformed_r)
        return result

    def _expand_vector(self, vector):
        result = bitarray(48, endian='big')
        result.setall(False)
        for i in xrange(0, 48):
            result[i] = vector[tables.EXPANSION_PERMUTATION[i] - 1]
        return result


    def _block6to4(self, block, s_number):
        result = bitarray(4, endian='big')
        result.setall(False)

        s_row = Encryptor.bitarray_to_int(block[0::5])
        s_column = Encryptor.bitarray_to_int(block[1:5])

        index = s_row * 16 + s_column

        b = tables.SUBSTITUTION[s_number][index]

        result = bitarray(Encryptor.to_binary(b))[60:64]

        return result


    def _block12to8(self, block_1, block_2, s_number):
        result = bitarray(8, endian='big')
        result.setall(False)

        s_row_1 = Encryptor.bitarray_to_int(block_1[0::5])
        s_column_1 = Encryptor.bitarray_to_int(block_1[1:5])
        index_1 = s_row_1 * 16 + s_column_1

        s_row_2 = Encryptor.bitarray_to_int(block_2[0::5])
        s_column_2 = Encryptor.bitarray_to_int(block_2[1:5])
        index_2 = s_row_2 * 16 + s_column_2

        #index_big = (index_2 << 4) + index_1
        index_big = (index_2 << 4) + index_1
        # index_big = Encryptor.bitarray_to_int(block_1+block_2)

        b = self._big_table[s_number][index_big]

        result = bitarray(Encryptor.to_binary(b))[56:64]

        return result


    def _form_big_table(self):
        self._big_table = [None] * 4

        for row in xrange(0, 4):
            ind = row * 2
            si = tables.SUBSTITUTION[ind]
            si2 = tables.SUBSTITUTION[ind + 1]
            row_s = [None] * 4096
            for i in xrange(0, 64):
                for j in xrange(0, 64):
                    ij = (j << 6) + i
                    #row_s[ij] = (si2[j] << 4) + si[i]
                    row_s[ij] = (si[j] << 4) + si2[i]
            self._big_table[row] = row_s


    def _do_permutation_p(self, vector):
        result = bitarray(32, endian='big')
        for i in xrange(0, 32):
            result[i] = vector[tables.PERMUTATION_P[i] - 1]
        return result


    def _do_final_permutation(self, vector):
        result = bitarray(64, endian='big')
        result.setall(False)
        for i in xrange(0, 64):
            result[i] = vector[tables.FINAL_PERMUTATION[i] - 1]
        return result


    @staticmethod
    def bitarray_to_int(bin_array):
        result = 0
        multiplier = 1
        if bin_array.endian() == 'big':
            for i in xrange(len(bin_array) - 1, -1, -1):
                result += multiplier * bin_array[i]
                multiplier *= 2
        elif bin_array.endian() == 'low':
            for i in xrange(0, len(bin_array)):
                result += multiplier * bin_array[i]
                multiplier *= 2
        return result


    @staticmethod
    def to_binary(n):
        return ''.join(str(1 & int(n) >> i) for i in range(64)[::-1])


    @staticmethod
    def cyclic_shift(vector, direction, n):
        result = None
        if direction == 'left':
            left_part = vector[:n]
            result = vector[n:]
            result += left_part
        elif direction == 'right':
            right_part = vector[len(vector) - n - 1:]
            result = vector[:n] + right_part
        else:
            raise NotImplementedError()
        return result
