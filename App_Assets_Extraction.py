#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from math import e
import os , re,io,shutil
import sys
import zipfile
import re
from androguard.decompiler.decompiler import DecompilerDAD
from androguard.core.analysis.analysis import Analysis
from androguard.misc import AnalyzeAPK 

#from matplotlib.pyplot import connect

#请先对basksmali.jar和apktool工具进行配置为绝对路径
bask = "./baksmali-2.4.0.jar"
apktool = "./apktool"
#匹配有端口资产
ExtranetA = re.compile(r'((((file|gopher|news|nntp|telnet|http|ftp|https|ftps|sftp)://)|(www\.))+(([a-zA-Z0-9\._-]+\.[a-zA-Z]{2,6})|([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}))(/[a-zA-Z0-9\&%_\./-~-]*)?:\d{0,9})')
ExtranetB = re.compile(r'((25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d):\d{0,9})')
#匹配无端口资产
ExtranetC = re.compile(r'(((file|gopher|news|nntp|telnet|http|ftp|https|ftps|sftp)://)|(www\.))+(([a-zA-Z0-9\._-]+\.[a-zA-Z]{2,6})|([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}))(/[a-zA-Z0-9\&%_\./-~-]*)?')
ExtranetD = re.compile(r'(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)')

# 多重规则去匹配数据
#匹配阿里osskeyid
aliyun_osskeyid = re.compile(r'(LTAI+[a-zA-Z0-9])')
#匹配腾讯coskeyid
tencent_coskeyid = re.compile(r'(AKID+[a-zA-Z0-9])')
#匹配vpnpass
#vpn_pass = re.compile(r'[v|V][p|P][n|N].*[pass|Pass|PASS|user|User|USER]') 

# 获取java方法的smali代码
# 传入参数类型 EncodedMethod
def get_method_smali_code(method):
    code = ""
    bc = method.get_code().get_bc()
    for b in bc.get_instructions():
        code = "{}{:30} {}\n".format(code, b.get_name(), b.get_output(bc.idx))
    return code

# 将Ltest/com/testdemo/UnSafeWebViewClient$3;这种转换为test.com.testdemo.UnSafeWebViewClient$3
def get_class_name_from_smali_name(name):
    class_name = name[1:-1]
    class_name = class_name.replace("/", ".")
    return class_name


def getclassname(strfile):
    
    # 读取当前文件第一行进行筛选
    try:
        with io.open(strfile, 'r', encoding='utf-8') as smali:
            for line in smali.readlines():
                one = line.find("L")
                two = line.find(";")
                newclass = line[one:two+1]
                return newclass

            # 如果是vpn类型的 需要把smali代码转换后存储
            
    except Exception as e:
        print(e)
def smali2java(_androguard_data:dict,filedName,file):
    
    
    ClassName = getclassname(file)
    
    dx: Analysis = _androguard_data['analysis']
    # classes = dx.find_classes(ClassName)
    # methodes = dx.classes[ClassName].get_methods()
    filed = dx.find_fields(classname=ClassName, fieldname=filedName)
    desc = "类名: "+ClassName+" 变量名: "+filedName +" 所在函数: "
    methodess = []
    for field1 in filed:
           
            for _, meth in field1.get_xref_write():
                #print("  write in {} -- {}".format(meth.class_name, meth.name))
                methodess.append(meth.name)
                desc += meth.name +" "
    for method1 in methodess:

        methods = dx.find_methods(classname=ClassName, methodname=str(method1),
                                    descriptor='.*')       
        for method in methods:
                try:
                    for class_obj, method_obj, offset in method.get_xref_from():
                            source = method_obj.get_source()
                            desc = "%s反编译的java代码为:\n```java\n%s\n```\n\n" % (desc, source.strip())
                            continue

                except Exception as e:
                    print(e)
                    return "smali2java 转换失败"

    return desc
    




# 定义一个匹配表
def testmach(line,ret_list):
 
    if ExtranetA.search(line):
        newstr = ExtranetA.search(line)
        ip = newstr[0]
        result = ip.rfind(":")
        #print(result)
        ret_list.append(' %s ' % (ip))
        return
    elif ExtranetB.search(line):
        newstr = ExtranetB.search(line)
        ip = newstr[0]
        result = ip.find(':')
        if result == 1 :
            print(ip)
            print(result)
            return
        #print(result)
        ret_list.append(' %s ' % (ip)) 
        return
    elif ExtranetC.search(line):
        newstr = ExtranetC.search(line)
        ip = newstr[0]
        result = ip.rfind(":")
        
        #print(result)
        ret_list.append(' %s ' % (ip)) 
        return
    elif ExtranetD.search(line):
        newstr = ExtranetD.search(line)
        ip = newstr[0]
        
        result = ip.find('.')
        if result == 1 :
            print(ip)
            print(result)
            return
        #print(result)
        ret_list.append(' %s ' % (ip)) 
        return
    elif aliyun_osskeyid.search(line) :
        newstr = aliyun_osskeyid.search(line)
        print(line)
        #print(result)
        ret_list.append('疑似阿里云osskeyid: %s ' % (line)+"\n") 
        return
    elif tencent_coskeyid.search(line):
        newstr = aliyun_osskeyid.search(line)
        print(line)
        #print(result)
        ret_list.append('疑似腾讯coskeyid: %s ' % (line)+"\n") 
        return
    # elif vpn_pass.search(line):
    #     newstr = vpn_pass.search(line)
    #     ip = newstr[0]
    #     strlocal = ip.find(":")
    #     filedName = ip[0:strlocal]

    #     desc = smali2java(_androguard_data,filedName,file)

    #     ret_list.append('疑似泄漏vpn账号密码 : %s ' % (desc)+"\n") 
    #     return 

#dex 使用basksmali 进行反编译
def Decompile_dex(filepath):
    try:
        
        str_cmd = "java -jar "+ bask +" d "+ filepath +" -o "+tool(filepath)
        print(str_cmd)
        os.system(str_cmd)
        
        return tool(filepath)
    except Exception as e:
        print(e)
        return "decompile excepiton fail"
#dex URL提取

def dex_search(file):
    ret_list = []
    line_num =0   

    try:
        with io.open(file, 'r', encoding='utf-8') as smali:
            for line in smali.readlines():
                if 'android.com' in line:
                    continue
                if 'google.com' in line:
                    continue
                if 'umeng' in line:
                    continue
                if 'adobe' in line:
                    continue
                if 'w3g' in line:
                    continue
                if 'apache' in line:
                    continue
                testmach(line,ret_list)
            # 如果是vpn类型的 需要把smali代码转换后存储
            
    except Exception as e:
        print(e)
    return ret_list
#dex main
def dex_url_extract(filepath):

    dex_magic  = b'\x64\x65\x78\x0A\x30\x33\x35\x00'
    magic_num = open(filepath, 'rb').read(8)
    if magic_num == dex_magic:
        try:
            dex_path = Decompile_dex(filepath)
            if dex_path == "decompile excepiton fail" :
                exit()
            savefile = dex_path+".md"
            for dirpath, _, filenames in os.walk(dex_path):
                    #跳过original目录
                    if dirpath.count("original") > 0:
                        continue
                    for filename in filenames:
                        #如果结尾不是smali或xml就跳出本次循环
                        # if (not filename.endswith('smali') and
                        #     not filename.endswith('xml') ):
                        #     continue
                        file = os.path.join(dirpath, filename)
                        #print(dirpath)
                        ret = dex_search(file)
                        if len(ret) !=0:
                            #如果找到了url 就以追加的形式写到文件中
                            #使用join 去除list并且添加换行
                            cont_str = '\n'.join(ret)
                            
                            f = io.open(savefile,'a')
                            f.write(cont_str)
        except Exception as e:
            print("fail")
            exit()
        print("url提取结果保存到: "+savefile)
        #删除缓存目录
        shutil.rmtree(dex_path) 
    else :
        print("不是有效的dex文件 请检查")    
#apk 使用apktool 进行反编译
def Decompile_apk(filepath):
    try:

        str_cmd = "java -jar "+apktool + " d  --only-main-classes "+ filepath +" -o "+tool(filepath)
        os.system(str_cmd)
        return tool(filepath)
    except Exception as e:
        return "decompile excepiton fail"

def so_search(file):

    try:
    
        result = os.popen("strings " +file +" | grep -E 'LTAI|http'")
        
        dirResult = tool(file)
        dirResult =dirResult +".md"
        res = result.read()
        f = io.open(dirResult,'a')
        f.write(res)
        f.close()
        result =so_url_filter(dirResult)
        #删除缓存文件
        os.remove(dirResult)
        return result
    except Exception as e:
        print(e)


#因为so使用的是strings 所以要筛选一下  
def so_url_filter(file):
    print(file)
    ret_list = []
    try:
        with io.open(file, 'rt', encoding='utf-8') as so:
            result = so.readlines()
            
            for line in result:
                #print(line)
                if 'android' in line:
                    continue
                if 'umeng' in line:
                    continue
                if 'adobe' in line:
                    continue
                testmach(line,ret_list)
                    
        return ret_list  
    except Exception as e:
        print(e)
    
#apk main
def apk_url_extract(filepath):
    try:
        apk_Decompile_path = Decompile_apk(filepath)

        # a, d, dx = AnalyzeAPK(filepath)
        # dad = DecompilerDAD(d, dx)
        # androguard_data = {'apk': a, 'dvm': d, 'analysis': dx, "dad": dad}
        savefile = filepath+".url.md"   
        for dirpath, _, filenames in os.walk(apk_Decompile_path):
                #跳过original目录
                if dirpath.count("original") > 0:
                    continue
                for filename in filenames:
                    
                    #如果结尾不是smali或xml就跳出本次循环
                    # if (not filename.endswith('smali') and
                    #     not filename.endswith('xml')):
                    #     continue

                    file = os.path.join(dirpath, filename)
                    if filename.endswith('so'):
                        ret = so_search(file)
                    if filename.endswith('dex'):
                        ret = dex_search(file)
                    else :
                        ret = dex_search(file)
                    if len(ret) !=0:
                        #如果找到了url 就以追加的形式写到文件中
                        #使用join 去除list并且添加换行
                        cont_str = '\n'.join(ret)
                        f = io.open(savefile,'a')
                        f.write(cont_str)
                        f.close()
                    
        print("url提取结果保存到: "+savefile)
        #删除缓存文件
        shutil.rmtree(apk_Decompile_path)
    except Exception as e:
            print(e)

# dex目录遍历提取url
# 注意需要遍历一个文件后 进行写入文件
# 反编译一个 搜索一个 结果写入文件
def dirdex_url_extract(filepath):
    new_filepath =filepath.replace("/","_")
    dirResult = filepath+".url.md"
    for root,dir,filename in os.walk(filepath) :
        for file in filename:
            Nfile = root +"/"+file
            path1 = os.path.abspath('.')
            print(path1)
            dex_magic  = b'\x64\x65\x78\x0A\x30\x33\x35\x00'
            magic_num = open(Nfile, 'rb').read(8)
            if magic_num == dex_magic:
                dex_Decompile_path = Decompile_dex(Nfile)
                for dirpath, _, filenames in os.walk(dex_Decompile_path):
                #跳过original目录
                    if dirpath.count("original") > 0:
                        continue
                    for filename in filenames:
                        #如果结尾不是smali活xml就跳出本次循环
                        # if filename.endswith('smali'):
                        #     continue
                        file = os.path.join(dirpath, filename)
                        ret = dex_search(file)
                        if len(ret) !=0:
                            #如果找到了url 就以追加的形式写到文件中
                            #使用join 去除list并且添加换行
                            cont_str = '\n'.join(ret)
                            f = io.open(dirResult,'a')
                            f.write(cont_str)
                #删除缓存目录 
                shutil.rmtree(dex_Decompile_path)

    print("url提取结果保存到: "+dirResult)

ipa_payload = ""

def unzipIpa(self,output_path):
        with zipfile.ZipFile(self,"r") as zip_files:
            zip_file_names = zip_files.namelist()
            zip_files.extractall(output_path)
            print("提取路径： " + output_path+"/"+zip_file_names[1]+"*")
            global ipa_payload
            ipa_payload = zip_file_names[0]
            return output_path+"/"+zip_file_names[1]
            

def ipa_url_extract(file):
    try:
        file_list = []
        #获取当前file的绝对路径
        absolute_filepath = os.path.abspath(file)

        ret_list = []
        print(absolute_filepath)
        len = absolute_filepath.rfind("/") 
        start = 0
        outfile = absolute_filepath[start:len]
        newipdir=""
        #解压ipa
        #解压需要添加对ipa中存在空格的文件修改并删除所有空格，否则会出现无法提取的问题
        if absolute_filepath.endswith(".ipa"):
            ipadir = unzipIpa(absolute_filepath,outfile)
            newipdir = ipadir.replace(" ", '')
            newipdir = os.path.join(ipa_payload, newipdir);
            os.rename(os.path.join(ipa_payload, ipadir), os.path.join(ipa_payload, newipdir))
            print("检测文件名空格问题")
            #zip解压提取后 对zip路径进行扫描 如果存在空格的文件 就删除空格
            for root, dirs, files in os.walk(newipdir):
                print("目录：" + root)
                for name in files:
                    NewFileName = name.replace(" ", '');
                    NewFileName = os.path.join(root, NewFileName);
                    os.rename(os.path.join(root, name), os.path.join(root, NewFileName))
                    file_list.append(NewFileName)
                for name in dirs:
                    print("文件目录：");
                    print(os.path.join(root))
                    # 如果是目录要继续检索
                    for tworoot, dirs, files in os.walk(root+name):
                        ## 判断目录是否存在空格 如果存在则对目录名进行修补
                        newroot =tworoot.replace(" ", '')
                        os.rename(tworoot,newroot)
                        print(newroot)
                        for name in files:
                            NewFileName = name.replace(" ", '');
                            NewFileName = os.path.join(newroot, NewFileName);
                            os.rename(os.path.join(newroot, name), os.path.join(newroot, NewFileName))
                            file_list.append(NewFileName)
                    

            #遍历解压的目录进行提取 首先是可执行文件
            #然后是其他的资源文件 js html xml
            dirResult = tool(newipdir)
            dirResult =file +".url.md"
            for file in file_list:
                    File_extension = os.path.splitext(file)[-1]
                    if '.png' in File_extension:
                        continue
                    if '.jpg' in File_extension:
                        continue
                    if '.jpeg' in File_extension:
                        continue
                    if '.gif' in File_extension:
                        continue
                    #newfile = newipdir+file
                    #result = os.popen("strings "+file + " | grep -E 'LTAI|http'")
                    print(file)
                    result = os.popen("strings  " +file + " | grep  -E '((((file|gopher|news|nntp|telnet|http|ftp|https|ftps|sftp)://)|(www\.))+(([a-zA-Z0-9\._-]+\.[a-zA-Z]{2,6})|([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}))(/[a-zA-Z0-9\&%_\./-~-]*)?:\d{0,9})|((25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d):\d{0,9})|(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)|(((file|gopher|news|nntp|telnet|http|ftp|https|ftps|sftp)://)|(www\.))+(([a-zA-Z0-9\._-]+\.[a-zA-Z]{2,6})|([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}))(/[a-zA-Z0-9\&%_\./-~-]*)?|LTAI|^wx\d{16}$' ") #-E LATI|
                    ret_list.append(' %s ' % (result.read()))

        else :
            dirResult =file +".url.md"
            print("iOS-ExecFile")
            print("当前提取文件名 "+file)
            result = os.popen("strings  " +file + " | grep -E '((((file|gopher|news|nntp|telnet|http|ftp|https|ftps|sftp)://)|(www\.))+(([a-zA-Z0-9\._-]+\.[a-zA-Z]{2,6})|([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}))(/[a-zA-Z0-9\&%_\./-~-]*)?:\d{0,9})|((25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d):\d{0,9})|(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)|(((file|gopher|news|nntp|telnet|http|ftp|https|ftps|sftp)://)|(www\.))+(([a-zA-Z0-9\._-]+\.[a-zA-Z]{2,6})|([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}))(/[a-zA-Z0-9\&%_\./-~-]*)?|LTAI|^wx\d{16}$' ") #-E LATI|
            ret_list.append(' %s ' % (result.read()))
            res = r'\n'.join(ret_list)
            f = io.open(dirResult,'a')
            f.write(res)
            f.close()
            #字符串过滤函数ipa_url_filter
            result = ipa_url_filter(dirResult)
            os.remove(dirResult)
            new_str =result
            result_f = open(dirResult,'w')
            cont_str = '\n'.join(new_str)
            result_f.write(cont_str)
            print("url提取结果保存到: "+dirResult)
            return

        res = r'\n'.join(ret_list)
        f = io.open(dirResult,'a')
        f.write(res)
        f.close()
        result = ipa_url_filter(dirResult)
        os.remove(dirResult)
        new_str =result
        result_f = io.open(dirResult,'w')
        cont_str = '\n'.join(new_str)
        result_f.write(cont_str)

        shutil.rmtree(outfile+"/"+ipa_payload)
        print("url提取结果保存到: "+dirResult)
    except Exception as e:
        print(e)
#因为ios使用的是strings 所以要筛选一下  
def ipa_url_filter(file):
   
    #print(file)
    ret_list = []
    try:
        with io.open(file, 'r', encoding='utf-8') as ios:
            for line in ios.readlines():
               
                if 'apple' in line:
                    continue
                if 'umeng' in line:
                    continue
                if 'adobe' in line:
                    continue
                if 'microsoft'in line:
                    continue
                if 'developer' in line:
                    continue
                if 'github.com' in line:
                    continue
                if 'flutter' in line:
                    continue
                # if 'http://' in line:
                #     testmach(line,ret_list)
                # if 'https://' in line:
                #     testmach(line,ret_list)
                testmach(line,ret_list)
                    
        return ret_list     
    except Exception as e:
        print(e)
    
def mainswitch(sw):
    

    if sw == "-a": #android
        sw_dex_apk_dir_ipa = sys.argv[2]
        print("Android") 

        
        strlen = len(sw_dex_apk_dir_ipa)
        #通过截取后缀来判断是文件/目录(虽然有些不太对 应该去判断魔术) 但是先用这个 后面完善了在去判断魔术标识头
        if sw_dex_apk_dir_ipa[strlen-4:strlen] ==".apk":
            print("apk")
            apk_url_extract(sw_dex_apk_dir_ipa)
        elif sw_dex_apk_dir_ipa[strlen-4:strlen] ==".dex":
            print("dex")
            dex_url_extract(sw_dex_apk_dir_ipa)
        elif os.path.isdir(sw_dex_apk_dir_ipa):
            print("文件夹")
            dirdex_url_extract(sw_dex_apk_dir_ipa)

        else :
            print("不符合提取文件标准，退出")
            exit()
    elif sw =="-i": #ios
            sw_dex_apk_dir_ipa = sys.argv[2]
            print("iOS-ipa")
            #print("ipa文件 只能是脱壳后的可执行文件,加固状态下的可执行文件不可以提取url")
            #1. 使用 strings 进行搜索
            ipa_url_extract(sw_dex_apk_dir_ipa)
    elif sw == "-h":
            print(" App资产提取工具")
            print(" -a  android 适配: 无壳/多dex/单dex")
            print(" -i  ios     适配: 脱壳后的可执行文件/脱壳后的ipa 需要依赖strings工具")
            print(" Android用法示例 python ./App_Assets_Extraction -a  apk/dex/dir ")
            print(" iOS用法示例 python ./App_Assets_Extraction   -i  /ipa ")
            print(" python ./App_Assets_Extraction -a/i  apk/ipa/dex/dir ")
    else :
        print(" 参数输入错误  -h help")
        exit()


def tool(file):
    newfile = file.replace("/","_")
    fstr = newfile.replace(".","_")
    return fstr
def anti_tool(file):
    newfile = file.replace("_","/")
    fstr = newfile.replace("_",".")
    return fstr

# ios
# 使用strings 读取可执行文件
typeA = re.compile(r'10\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])$')

if __name__ == "__main__":

    if len(sys.argv) == 1 :
        print(" App资产提取工具")
        print(" -a  android 适配: 无壳/多dex/单dex")
        print(" -i  ios     适配: 脱壳后的可执行文件/脱壳后的ipa 需要依赖strings工具")
        print(" Android用法示例 python ./App_Assets_Extraction.py -a  apk/dex/dir ")
        print(" iOS用法示例 python ./App_Assets_Extraction.py   -i  /ipa ")
        print(" python ./App_Assets_Extraction.py -a/i  apk/ipa/dex/dir ")
        exit()

    sw = sys.argv[1]

    mainswitch(sw)







    
