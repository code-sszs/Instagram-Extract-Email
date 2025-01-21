import requests ,  re , os , sys, time


logo = r"""

                         ___ ____     ____  ____ ____ _________  
                        |_ _/ ___|   / __ \/ ___/ ___|__  / ___| 
                         | | |  _   / / _` \___ \___ \ / /\___ \ 
                         | | |_| | | | (_| |___) |__) / /_ ___) |
                        |___\____|  \ \__,_|____/____/____|____/ 
                                     \____/                      
                                    
                                    Instagram Extract Email
                                    Coded By: @sszs
"""
class IG:
    def __init__(self):
        print(logo + "\n")
        
    def Login(self,user,passw,proxy=None):
        sess = requests.Session()
        if proxy:
            print("Using Proxy: {}".format(proxy))
            proxies = {'http': 'http://{}'.format(proxy), 'https': 'https://{}'.format(proxy)}
            sess.proxies = {'http': 'http://{}'.format(proxy), 'https': 'https://{}'.format(proxy)}
        try:
            url = "https://www.instagram.com/accounts/login/ajax/"
            payload = 'username={}&enc_password=%23PWD_INSTAGRAM_BROWSER%3A0%3A0%3A{}&queryParams=%7B%7D&optIntoOneTap=false'.format(user, passw)
            headers = {
                'authority': 'www.instagram.com',
                'content-type': 'application/x-www-form-urlencoded',
                'accept': '*/*',
                'user-agent': '',
                'x-requested-with': 'XMLHttpRequest',
                'x-csrftoken': 'missing',
                'x-ig-app-id': '936619743392459',
                'origin': 'https://www.instagram.com',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-mode': 'cors',
                'sec-fetch-dest': 'empty',
                'referer': 'https://www.instagram.com/',
                'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
            }
            response = sess.post(url, headers=headers, data=payload)
            
            mid = response.cookies['mid']
            if "checkpoint_required" in response.text:
                check_point = re.findall(r'"checkpoint_url":"(.*?)"', response.text)[0]
                data = "choice=1&sigp_to_hl=True"
                headers = {
                'Host': 'www.instagram.com',
                'content-type': 'application/x-www-form-urlencoded',
                'accept': '*/*',
                'cookie': f'wd=1314x849; csrftoken=missing; mid={mid}; ig_nrcb=1',
                'user-agent': '',
                'x-requested-with': 'XMLHttpRequest',
                'X-Csrftoken': 'missing',
                'x-ig-app-id': '936619743392459',
                'X-Instagram-Ajax': '1019461813',
                'origin': 'https://www.instagram.com',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-mode': 'cors',
                'sec-fetch-dest': 'empty',
                'referer': 'https://www.instagram.com/',
                'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
                }
                req = sess.post("https://www.instagram.com/api/v1{}".format(check_point.replace('action','web/reset')) , data=data ,cookies=response.cookies, headers=headers)
                if "email" in req.text and "AcknowledgeForm" in req.text:
                    email = re.findall(r'"email":"(.*?)"', req.text)[0]
                    oldEmail = re.findall(r'"old_email":"(.*?)"', req.text)[0]
                    with open("@{}-info.txt".format(user), "w") as f:
                        f.write(f"Email: {email}\nOld Email: {oldEmail}")
                elif "Oops, an error occurred." in req.text:
                    print("User Blocked: {}".format(user))
            elif '"user":true,"authenticated":false,"status":"ok"' in response.text:
                print("Login Failed: {}\nMaybe IP Blocked Try With Proxy Or Using VPN".format(user))
                time.sleep(0.7)
                self.Option()
        except Exception as e:
            self.Login(user,passw)


    def Option(self):
        print("1. Login")
        print("2. Exit")
        option = input("Select Option: ")
        if option == "1":
            print("1. Without Proxy\n2. With Proxy")
            option = input("Select Option: ")
            if option == "1":
                user = input("Username: ")
                passw = input("Password: ")
                self.Login(user,passw)
            elif option == "2":
                user = input("Username: ")
                passw = input("Password: ")
                proxy = input("Proxy: ")
                self.Login(user,passw,proxy)
            else:
                print("Invalid Option")
                self.Option()
        elif option == "2":
            sys.exit()
        else:
            print("Invalid Option")
            self.Option()

if __name__ == '__main__':
    IG().Option()