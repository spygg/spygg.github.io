# -*- coding: cp936 -*-
import os
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import zstandard as zstd
import sys
import shutil

# 用auto-py-to-exe 打包--one-file模式下的资源文件重定位问题
def get_resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        base_path = sys._MEIPASS  # 临时解压目录
    else:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def scanDump(directory, subfix):
    files_list = []
    for root, sub_dirs, files in os.walk(directory):
        for special_file in files:
            if subfix:
                if special_file.endswith(subfix):
                    files_list.append(os.path.join(root, special_file))
            else:
                pass

    return files_list


def callMinidump(files_list, exe):

    caddr = ""
    index = 0
    lines = []

    for file in files_list:
        index = index + 1
        dup = os.popen("%s %s symbols" % (get_resource_path("minidump_stackwalk.exe"), file))
        with open("errorlog_%d.txt" % index, "w") as f:
            while True:
                line = dup.readline()
                if line:
                    lines.append(line)
                    if line.find("%s +" % exe) != -1:
                        eipline = dup.readline()
                        lines.append(eipline)

                        if eipline:
                            eip = eipline.strip().split('   ')[0].strip()
                            eipline = eip.split('=')
                            addr = eipline[1]
                            #print(addr, eipline)
                            #if eipline[0] == 'eip':
                            caddr += addr.replace("0x", "")
                            
                        else:
                            break
                else:
                    break
            
            pass

            addrexe = "%s -f -e %s -a %s" % (get_resource_path("addr2line.exe"), exe, caddr)
            addr2line = os.popen(addrexe)

            f.write(addrexe)
            f.write("\n\n")
            f.write(addr2line.read())

            f.write("\n\n##############################\n\n")
            for line in lines:
                f.write(line)


def callObjdump(exe):
    asm = os.popen("%s -S %s > __%s.asm" % (get_resource_path("objdump.exe"), exe, exe))# > aaa.asm")
    # with open("%s.asm" % exe, "wb") as f:
    #     f.write(asm.read())   


def compress_then_encrypt(data: bytes, key: bytes) -> bytes:
    """先压缩，再加密"""
    # 1. 使用 zstd 压缩数据
    cctx = zstd.ZstdCompressor()
    compressed_data = cctx.compress(data)
    
    # 2. 生成随机初始化向量 (IV)
    iv = os.urandom(16)  # AES 的 IV 通常为 16 字节
    
    # 3. 使用 AES-CBC 加密（需填充）
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(compressed_data) + padder.finalize()
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # 4. 返回 IV + 加密数据（便于后续解密）
    return iv + encrypted_data

def decrypt_then_decompress(encrypted_data: bytes, key: bytes) -> bytes:
    """先解密，再解压"""
    # 1. 提取 IV 和加密数据
    iv = encrypted_data[:16]
    encrypted_payload = encrypted_data[16:]
    
    # 2. 使用 AES-CBC 解密
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_payload) + decryptor.finalize()
    
    # 3. 去除填充
    unpadder = padding.PKCS7(128).unpadder()
    compressed_data = unpadder.update(padded_data) + unpadder.finalize()
    
    # 4. 使用 zstd 解压
    dctx = zstd.ZstdDecompressor()
    return dctx.decompress(compressed_data)




def compress_and_encrypt_file(file_path: str, out_path: str,  key: bytes) -> bytes:
    #with open('key.dat', 'wb') as fk:
    #    fk.write(key)
        
    with open(file_path, 'rb') as f:
        original_data = f.read()
        
        # 加密 + 压缩
        encrypted = compress_then_encrypt(original_data, key)
        print(f"加密后大小: {len(encrypted)} bytes (原始: {len(original_data)} bytes)")
    

        with open(out_path, 'wb') as fs:
            fs.write(encrypted)


def decrypt_then_decompress_file(file_path: str, out_path: str,  key: bytes) -> bytes:
    with open(file_path, 'rb') as f:
        print('打开文件 %s, %s' % (file_path, out_path))

        original_data = f.read()
    
        # 加密 + 压缩
        decrypted = decrypt_then_decompress(original_data, key)    

        with open(out_path, 'wb') as fs:
            fs.write(decrypted)

    

def dowork(file_path: str, mode: str):

    #file_path = 'radiometer.exe'
    debug_path = '%s.debug' %file_path
    out_path = '%s.zip' % debug_path

    #这里修改秘钥
    #32个字节长度的加密秘钥#bytes([])

    key = []

    if len(key) != 32:
        raise Exception("key 必填")
        
    
    if mode == 'compress':
        #1. 执行 objcopy 分离 debug信息
        os.system('objcopy --only-keep-debug %s %s.debug' % (file_path, file_path))


        #2. 执行 s
        os.system('strip --strip-debug %s' % file_path)


        #3. objcopy
        os.system('objcopy --add-gnu-debuglink %s.debug %s' % (file_path, file_path))

        #4. 加密压缩
        compress_and_encrypt_file(debug_path, out_path, key)
    
    else:
        decrypt_then_decompress_file(out_path, debug_path, key)




def dostripDebug(file_path):
    print("当前路径", os.getcwd(), len(sys.argv), sys.argv)
    
    mode = ''
    work_dir = '.'
  
     
    if len(sys.argv) > 2:
        mode = sys.argv[2]

    if len(sys.argv) > 3:
        work_dir = sys.argv[3]

    if len(sys.argv) < 3:
        #os.system('%s getdebug' % (file_path))
        print("解密", file_path)


    os.chdir(work_dir)
    print("切换后路径", os.getcwd())

    if not os.path.exists(file_path):
        print("\n\n文件 %s 不存在返回.........." % file_path)
        return False

    dowork(file_path, mode)

    ########################################

    return True



def doCrashanalysis(exename):
    l = scanDump(".", ".dmp")
        
    print("analysis %s" % exename)
    callMinidump(l, exename)
    #callObjdump(exename)

if __name__ == "__main__":
    print("#################################################")
    print("crashanalysis 崩溃.exe")
    print("#################################################\n\n")
    
    exename = "默认.exe"
    if len(sys.argv) > 1:
        exename = sys.argv[1]
        
    if dostripDebug(exename):
        doCrashanalysis(exename)
