# 导入IDA Pro API和相关库
import idaapi
from idaapi import *  # 导入IDA API中的所有函数
import idautils      # IDA工具函数
import idc           # IDC脚本兼容函数
from idc import *    # 导入IDC中的所有函数
from capstone import *  # 反汇编引擎
from keystone import *  # 汇编引擎
import json          # JSON处理

def xor_bytes(offset_result, offset_a2, length):
    """
    对两个内存区域进行异或操作并写回结果
    
    参数:
        offset_result: 结果内存地址(将被修改)
        offset_a2: 异或操作数内存地址
        length: 要异或的字节长度
    
    返回:
        结果内存地址
    """
    # 获取两个内存区域的数据
    result = idc.get_bytes(offset_result, length)
    a2 = idc.get_bytes(offset_a2, length)

    # 转换为可修改的bytearray
    result = bytearray(result)
    a2 = bytearray(a2)

    # 处理8字节对齐部分
    v3 = length & 7  # 计算非8字节对齐的剩余长度
    if length >= 8:
        v4 = 7
        while True:
            # 批量处理8字节异或
            result[v4 - 7] ^= a2[0]
            result[v4 - 6] ^= a2[1]
            result[v4 - 5] ^= a2[2]
            result[v4 - 4] ^= a2[3]
            result[v4 - 3] ^= a2[4]
            result[v4 - 2] ^= a2[5]
            v5 = v4
            result[v4 - 1] ^= a2[6]
            v6 = result[v4]
            v4 += 8
            result[v5] = a2[7] ^ v6

            if (v3 - length + v4) == 7:
                break

    # 处理剩余非8字节对齐部分
    if (length & 7) != 0:
        v7 = length - v3
        while v3 != 0:
            v8 = v7
            v9 = result[v7]
            v10 = a2[0]
            a2 = a2[1:]  # 移动指针
            v3 -= 1
            v7 += 1
            result[v8] = v10 ^ v9

    # 将结果写回内存
    for i in range(length):
        ida_bytes.patch_byte(offset_result + i, result[i])
    return offset_result

def get_calls_to(func_ea):
    """
    获取所有调用指定函数的指令地址，并分析相关参数
    
    参数:
        func_ea: 目标函数的起始地址
    """
    # 遍历所有引用该函数的交叉引用
    for xref in idautils.XrefsTo(func_ea):
        call_ea = xref.frm  # 调用指令的地址
        
        # 只处理BL(分支链接)指令
        if idc.print_insn_mnem(call_ea) != "BL":
            continue
            
        # 初始化变量
        str_addr = 0    # 字符串地址
        key_addr = 0    # 密钥地址
        str_len = 0     # 字符串长度
        adrp_str = 0    # ADRP指令计算的字符串基址
        adrp_key = 0    # ADRP指令计算的密钥基址
        
        # 逆向分析调用前的指令，获取参数
        current_ea = call_ea
        while True:
            current_ea = prev_head(current_ea)  # 获取前一条指令
            
            mnem = idc.print_insn_mnem(current_ea)  # 获取指令助记符
            
            # 处理MOV指令(通常设置长度)
            if mnem == "MOV":
                op_1_type = idc.get_operand_value(current_ea, 0)
                if op_1_type == 131:  # 检查是否是设置长度的指令
                    str_len = idc.get_operand_value(current_ea, 1)
            
            # 处理ADD指令(计算最终地址)
            if mnem == "ADD":
                op_1_type = idc.get_operand_value(current_ea, 0)
                if op_1_type == 130:  # 密钥地址
                    key_addr = idc.get_operand_value(current_ea, 2)
                if op_1_type == 129:  # 字符串地址
                    str_addr = idc.get_operand_value(current_ea, 2)
            
            # 处理ADRP指令(计算基址)
            if mnem == "ADRP":
                op_1_type = idc.get_operand_value(current_ea, 0)
                if op_1_type == 130:  # 密钥基址
                    adrp_key = idc.get_operand_value(current_ea, 1)
                    key_addr = adrp_key + key_addr
                if op_1_type == 129:  # 字符串基址
                    adrp_str = idc.get_operand_value(current_ea, 1)
                    str_addr = adrp_str + str_addr
            
            # 当所有必要信息都获取到时退出循环
            if adrp_str != 0 and adrp_key != 0 and str_len != 0:
                break
        
        # 调用xor_bytes函数进行异或解密
        xor_bytes(str_addr, key_addr, str_len)

# 需要解密的函数地址列表
decode_adders = [
    0x4B5E8, 0x54298, 0x5C4EC, 0x64800, 0x72290, 0x741C8, 0x7EF7C, 0x9A5BC, 
    0x9FBE8, 0xBCC48, 0xC8978, 0xED3F4, 0xF8910, 0x146550, 0x16A6C8, 0x1A07A8, 
    0x1EF354, 0x204D44, 0x206CCC, 0x2079E4, 0x20B034, 0x21F6B0, 0x220A10, 
    0x22912C, 0x23A058, 0x241010, 0x2432B8, 0x25FCC8, 0x262624, 0x264E44, 
    0x2680D0, 0x26C114, 0x26D140, 0x274E98, 0x2796EC, 0x27D0EC, 0x2863B0, 
    0x28D600, 0x28FDE0, 0x2922F8, 0x298974, 0x299230, 0x2A0900, 0x2E0DA4, 
    0x2E13FC, 0x2E6DA4, 0x2E7910, 0x2EB3AC, 0x2EDC64, 0x2EE324, 0x2EE55C, 
    0x2EF460, 0x2EFE0C, 0x2F0D08, 0x2F12E0, 0x2F15D0, 0x2F36D0, 0x2F40EC, 
    0x2F82B4, 0x2FA324, 0x2FB534, 0x2FC344, 0x2FE37C, 0x2FFA6C, 0x300C24, 
    0x3031AC, 0x303D3C, 0x304CFC, 0x305028, 0x306DA0, 0x307140
]

# 遍历所有目标函数，处理它们的调用
for addr in decode_adders:
    get_calls_to(addr)

print("end")  # 解密完成