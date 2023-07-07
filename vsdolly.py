# encoding:utf-8
import os
from struct import *
from binary import BinaryStream
import sys

zip_eocd_rec_min_size = 22

zip_eocd_rec_sig = 0x06054b50

zip_eocd_central_dir_size_offset = 12

zip_eocd_central_dir_offset_offset = 16

zip_eocd_comment_length_offset = 20

uint16_max_value = 0xffff

sign_v2_magic_size = 16

target_value = "test"

target_id = 0x881155ff

# apk_file_path = "app-release.apk"

# dest_apk_file = "dest_client.apk"



if __name__ == '__main__':
    apk_file_path = sys.argv[1]
    dest_apk_file = sys.argv[2]

    print("%s ----->>>>> %s", apk_file_path, dest_apk_file)

    apk_file = open(apk_file_path, "rb+")
    apk_stream = BinaryStream(apk_file)
    apk_file_size = os.path.getsize(apk_file_path)

    print("apk file size is", apk_file_size)
    """
    获取EndOfCentralDirectoryRecord
    EOCD:
    offset|bytes|description
       0  |  4  |End of directory signature = 0x06054b50
       4  |  2  |Number of this disk
       6  |  2  |Disk where central directory starts
       8  |  2  |Number of central directory records
      10  |  2  |Total number of central directory records
      12  |  4  |Size of central directory(bytes)
      16  |  4  |Offset of start of central directory
      20  |  2  |Comment length(n)
      22  |  n  |Comment
    """
    max_comment_length = min(apk_file_size - zip_eocd_rec_min_size, uint16_max_value)
    print("max comment length is", max_comment_length)
    eocd_length = 22
    ecod_start_pos = apk_file_size - zip_eocd_rec_min_size
    while eocd_length < max_comment_length:
        apk_stream.seek(ecod_start_pos - eocd_length, 0)
        if apk_stream.read_uint32() == zip_eocd_rec_sig:
            break
        i = eocd_length + 1
    ecod_start_pos = ecod_start_pos + eocd_length
    print("ecod start position is", ecod_start_pos)

    apk_stream.seek(ecod_start_pos + zip_eocd_comment_length_offset, 0)
    comment_length = apk_stream.read_uint16()
    print("comment length is", comment_length)
    ecod_length = zip_eocd_rec_min_size + comment_length
    print("ecod_length", ecod_length)
    """
    获取central dir
    """
    apk_stream.seek(ecod_start_pos + zip_eocd_central_dir_size_offset)
    central_dir_size = apk_stream.read_uint32()
    print("central_dir_size is", central_dir_size)
    apk_stream.seek(ecod_start_pos + zip_eocd_central_dir_offset_offset)
    central_dir_offset = apk_stream.read_uint32()
    print("central_dir_offset is", central_dir_offset)
    """
    获取sign block v2
    Sign Block V2:
    offset|bytes|description
       0  |  8  |size of block (不含次字段的长度)
       8  |  n  |ID-Value Pair
      8+n |  8  |size of block
     8+n+8|  16 |magic(h8=0x3234206b636f6c42,l8=0x20676953204b5041)
    
    ID-Value Pair:
    offset|bytes|description
       0  |  8  |size
       8  |  4  |Id
      12  |  n  |value (n = size - 4)
    """
    apk_stream.seek(central_dir_offset - sign_v2_magic_size)
    sign_v2_magic_l = apk_stream.read_uint64()
    sign_v2_magic_h = apk_stream.read_uint64()
    print("sign_v2_magic_h is", hex(sign_v2_magic_h))
    print("sign_v2_magic_l is", hex(sign_v2_magic_l))
    apk_stream.seek(central_dir_offset - sign_v2_magic_size - 8)
    size_of_sign_v2_block = apk_stream.read_uint64()
    print("size_of_sign_v2_block is", size_of_sign_v2_block)
    """
    尝试获取sign block v2的起始位置,需要额外减去一个size_of_sign_v2_block的长度
    read all id-value:
    uint64:长度前缀,会计算id+value的长度
    uint32:id
    变长：value
    """
    sign_v2_start_pos = central_dir_offset - size_of_sign_v2_block - 8
    next_id_value_pos = sign_v2_start_pos + 8
    id_value_end_position = central_dir_offset - 24
    while next_id_value_pos < id_value_end_position:
        apk_stream.seek(next_id_value_pos)
        size = apk_stream.read_uint64()
        print("size is", size)
        block_id = apk_stream.read_uint32()
        print("id =", hex(block_id))
        next_id_value_pos = next_id_value_pos + 8 + size

    """
    开始写文件，这里测试往id-value字段里写入:
    0x881155ff - test
    """
    apk_stream.seek(0)

    target_apk = open(dest_apk_file, "wb")
    target_apk_stream = BinaryStream(target_apk)
    """
    先写入Content of ZIP entries
    """
    content_of_zip_entries_size = apk_file_size - ecod_length - central_dir_size - size_of_sign_v2_block - 8
    print("content_of_zip_entries_size is", content_of_zip_entries_size)
    target_apk_stream.write_bytes(apk_stream.read_bytes(content_of_zip_entries_size))
    """
    构建新的sign_block_v2并写入
    新的sign_block_v2需要重写size_of_block,添加ID-Value字段
    """
    new_id_value_size = 8 + 4 + len(target_value)
    """
    写入新的size_block_of_sign
    """
    target_apk_stream.write_uint64(new_id_value_size + size_of_sign_v2_block)
    """
    写入原来的id-value部分
    """
    apk_stream.seek(sign_v2_start_pos + 8)
    target_apk_stream.write_bytes(apk_stream.read_bytes(size_of_sign_v2_block - 24))
    """
    写入新的id-value部分
    """
    target_apk_stream.write_uint64(new_id_value_size - 8)
    target_apk_stream.write_uint32(target_id)
    target_apk_stream.write_string(target_value)
    """
    写入写入新的size_block_of_sign
    """
    target_apk_stream.write_uint64(new_id_value_size + size_of_sign_v2_block)
    """
    写入magic
    """
    target_apk_stream.write_uint64(0x20676953204b5041)
    target_apk_stream.write_uint64(0x3234206b636f6c42)
    """
    写入central_of_directory
    """
    apk_stream.seek(central_dir_offset)
    target_apk_stream.write_bytes(apk_stream.read_bytes(central_dir_size))
    """
    修改central_dir_offset,写入EOCD
    """
    apk_stream.seek(ecod_start_pos)
    """
    先写入EOCD前12字节
    """
    target_apk_stream.write_bytes(apk_stream.read_bytes(16))
    """
    写入新的central_dir_offset,4字节
    """
    print("new_central_dir_offset", central_dir_offset + new_id_value_size)
    target_apk_stream.write_uint32(central_dir_offset + new_id_value_size)
    """
    写入余下的字节
    """
    apk_stream.seek(ecod_start_pos + 20)
    target_apk_stream.write_bytes(apk_stream.read_bytes(ecod_length - 20))
    target_apk_stream.close()

    print("finish")
