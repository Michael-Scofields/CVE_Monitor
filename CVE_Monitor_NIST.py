# -*- coding:utf-8 -*-
import re
import time
import json
import requests
from operator import itemgetter
from bs4 import BeautifulSoup
from translate import Translator
import urllib3
urllib3.disable_warnings()

# sess = requests.session()
# sess.keep_alive = False

requests.adapters.DEFAULT_RETRIES = 5


class SearchCVE:
    def __init__(self, CVE):
        self.info = True
        self.CVE = CVE
        self.url = "https://nvd.nist.gov/vuln/detail/{}".format(self.CVE)
        self.score = ""
        self.vector = ""
        self.detail = ""
        self.affected = ""
        self.context = ""

    def trans(self, context):    # 翻译IP频率限制，按需弃用
        translator = Translator(to_lang="chinese")
        translation = translator.translate(context)
        return translation

    def run(self):
        self.get_cve_description()
        if any(x != "Null" for x in(self.score, self.vector, self.detail, self.affected, self.context)) :
            pass
            # self.score = self.trans(self.score)    # 翻译IP频率限制，按需弃用
        return self.info, self.score, self.vector, self.detail, self.affected, self.context

    def get_cve_description(self):
        try:
            # response = sess.get(self.url).text
            response = requests.get(self.url).text
            if "Not Found" in response:
                self.score = self.vector = self.detail = self.affected = self.context = "Null"
                self.info = False
            else:
                soup = BeautifulSoup(response, "lxml")

                cvss = soup.body.findAll('a', {'data-testid': "vuln-cvss3-panel-score"})
                self.score = cvss[0].text if len(cvss) == 1 else "Null"
                self.detail = "https://nvd.nist.gov{}".format(cvss[0]['href'])

                cvss_v = soup.body.findAll('span', {'data-testid': "vuln-cvss3-nist-vector"})
                self.vector = cvss_v[0].text if len(cvss_v) == 1 else "Null"

                affect = soup.body.findAll('input', {'id': "cveTreeJsonDataHidden"})
                tmp = affect[0]['value']
                self.affected = re.findall(r'cpe22Uri":"(.*?)"', tmp, re.S)

                description = soup.body.findAll('p', {'data-testid': "vuln-description"})
                self.context = description[0].text.replace("** DISPUTED **", "") if len(description) == 1 else "Null"
        except Exception as e:
            self.score = self.vector = self.detail = self.affected = self.context = "Null"
            print(f"[-] Error Data Format! Pass ...\n{e}")


def getNews():
    year = time.strftime("%Y", time.localtime(time.time()))
    try:
        api = f"https://api.github.com/search/repositories?q=CVE-{year}&sort=updated"
        # response = sess.get(api, timeout=10, verify=False).text
        response = requests.get(api, timeout=10, verify=False).text
        data = json.loads(response)
        return data
    except Exception:
        print(f"[-] Github Connection Failed! Please Wait ...")
        time.sleep(60)
        return False
    return True


def getName(index):
    item = items[index]
    iid = item['id']
    try:
        cve_reg = re.compile(r'(cve-\d+-\d+)', re.IGNORECASE)
        cve_name = re.findall(cve_reg, item['name'])[0]
    except Exception:
        cve_name = item['name']
    svn_url = item['svn_url']
    poc_des = item['description']
    return iid, cve_name, svn_url, poc_des


def sendMsg(t, iid, cve_name, score, vector, detail, affected, context, svn_url, poc_des):
    t = t
    send_url = f"https://sc.ftqq.com/{SCKEY}.send"
    details = f'''
    [Time] =》 {t}\n\n
    [ID] =》 {iid}\n\n
    [CVE Num] =》 {cve_name}\n\n
    [Base Score] =》 {score}\n\n
    [Vector] =》 {vector}\n\n
    [Detail] =》 {detail}\n\n
    [Affected] =》 {affected}\n\n
    [Description] =》 {context}\n\n
    [POC&EXP] =》 {svn_url}\n\n
    [Description] =》 {poc_des}\n\n
    '''
    data = {
        "text": "[Michael] | CVE Monitor",
        "desp": details
    }
    r = requests.post(send_url, data=data)
    status = r.status_code
    print("[*] Send Message | Status: {}".format(status))


if __name__ == '__main__':
    SCKEY = ""
    total = 640  # 初始化
    title = '''
  ______     _______     __  __             _ _
 / ___\ \   / / ____|   |  \/  | ___  _ __ (_) |_ ___  _ __
| |    \ \ / /|  _|     | |\/| |/ _ \| '_ \| | __/ _ \| '__|
| |___  \ V / | |___    | |  | | (_) | | | | | || (_) | |
 \____|  \_/  |_____|___|_|  |_|\___/|_| |_|_|\__\___/|_|
                   |_____|
            '''
    print(title)
    while True:
        t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
        print(f"[*] Try [{t}] ...")
        data = getNews()
        if not data:
            continue
        if data['total_count'] > total:
            items = sorted(data['items'], key=itemgetter('id'), reverse=True)
            num = data['total_count'] - total
            print(f'[+] Discover new records：{num}')
            for n in range(0, num):
                iid, cve_name, svn_url, poc_des = getName(n)
                s = SearchCVE(cve_name)
                info, score, vector, detail, affected, context = s.run()
                print(f'\n[+] ID：{iid}')
                print(f'[+] CVE Num：{cve_name}')
                print(f'[+] Base Score：{score}')
                print(f'[+] Vector：{vector}')
                print(f'[+] Detail：{detail}')
                print(f'[+] Affected：{affected}')
                print(f'[+] Description：{context}')
                print(f'[+] POC&EXP：{svn_url}')
                print(f'[+] Description：{poc_des}')
                if not info:
                    print(f"[-] Get CVE Details Failed! Pass ...")
                sendMsg(t, iid, cve_name, score, vector, detail, affected, context, svn_url, poc_des)
            total = data['total_count']
        else:
            print(f'[-] Not Found!')
        print("\n[*] Wait ...")
        time.sleep(600)
