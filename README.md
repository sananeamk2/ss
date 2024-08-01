import ctypes
import secrets
import string
import threading
import uuid
import requests
import pyfiglet
import httpx
import random
import time
from uuid import uuid4
from httpx import create_ssl_context
from httpx import Client
from contextlib import contextmanager
from typing import Final, Dict
from ssl import SSLContext
from typing import Optional
from oauthlib import oauth1
from urllib.parse import urlencode
import imaplib
import email
from email.header import decode_header
import re
from datetime import datetime
import threading
import socks

capsolver_api_key = "CAP-61EFEB4F412C70AB4F2089BADD1699B9"
kopeechka_api_key = "15f3de0677f0145323f136724c4b9622"
proxy = ""
ip_reset = "s"
use_imap = "y"
run_threads = 20
nameselec = "vn"

LIBRARY = ctypes.CDLL("./instrumentation.so")

client_version = "10.47.1"
accept_lang = "tr"
m_accept_lang = "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7"
r_os = "17.5.1"
x_twitter_client = "Twitter-iPhone"
user_agent = f"Twitter-iPhone/{client_version} iOS/{r_os} (Apple;iPhone15,2;;;;;1;2020)"
system_user_agent = f"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/21F90 Twitter for iPhone/{client_version}"
display_size = '1179x2556'
authorization = "AAAAAAAAAAAAAAAAAAAAAAj4AQAAAAAAPraK64zCZ9CSzdLesbE7LB%2Bw4uE%3DVJQREvQNCZJNiz3rHO7lOXlkVOQkzzdsgu6wWgcazdMUaGoUGm"

FLOW_INIT_PAYLOAD: Final[Dict] = {
    "component_versions": {
        "spacer": 1,
        "progress_indicator": 1,
        "settings_group": 1,
        "card_wrapper": 1,
        "image": 1,
        "action": 1,
        "button": 1,
        "inline_callout": 1,
        "button_item": 1,
        "precise_location": 1,
        "tweet": 1,
        "inline_feedback": 1,
        "inline_tooltip": 1,
        "user": 1,
        "list": 1,
        "destructive_action": 1,
        "static_text": 1,
        "alert_example": 1,
        "boolean": 1,
        "info_item": 1,
        "toggle_wrapper": 1,
    },
    "input_flow_data": {
        "flow_context": {"start_location": {"location": "splash_screen"}}
    },
    "subtask_versions": {
        "enter_date": 1,
        "sign_up": 2,
        "enter_username": 3,
        "alert_dialog": 1,
        "choice_selection": 6,
        "privacy_options": 1,
        "user_recommendations_list": 5,
        "upload_media": 1,
        "tweet_selection_urt": 1,
        "action_list": 2,
        "update_users": 1,
        "select_banner": 2,
        "js_instrumentation": 1,
        "standard": 1,
        "settings_list": 7,
        "app_locale_update": 1,
        "open_home_timeline": 1,
        "generic_urt": 3,
        "wait_spinner": 3,
        "menu_dialog": 1,
        "open_account": 2,
        "single_sign_on": 1,
        "open_external_link": 1,
        "select_avatar": 4,
        "enter_password": 6,
        "cta": 7,
        "open_link": 1,
        "user_recommendations_urt": 4,
        "show_code": 1,
        "location_permission_prompt": 2,
        "sign_up_review": 5,
        "in_app_notification": 1,
        "security_key": 3,
        "phone_verification": 5,
        "contacts_live_sync_permission_prompt": 3,
        "check_logged_in_account": 1,
        "enter_phone": 2,
        "enter_text": 5,
        "enter_email": 2,
        "web_modal": 2,
        "notifications_permission_prompt": 4,
        "end_flow": 1,
        "alert_dialog_suppress_client_events": 1,
        "email_verification": 3,
    },
}
GENERAL_PARAMS: Final[Dict] = {
    "ext": "highlightedLabel,mediaColor",
    "include_entities": "1",
    "include_profile_interstitial_type": "true",
    "include_profile_location": "true",
    "include_user_entities": "true",
    "include_user_hashtag_entities": "true",
    "include_user_mention_entities": "true",
    "include_user_symbol_entities": "true",
}

print("\033[1;33m" + pyfiglet.figlet_format("WinBY - X") + "\033[0m")

def check_email(smail, pwd, attempt=0, max_attempts=50):
    try:
        mail = imaplib.IMAP4_SSL('imap-mail.outlook.com')
        mail.login(smail, pwd)
        print("\033[1;33m[+] imap bağlandı 50 Saniye bekleniyor.\033[0m ")
    except imaplib.IMAP4.error as e:
        if attempt < max_attempts - 1:
            return check_email(smail, pwd, attempt + 1, max_attempts)
        else:
            print("\033[0;31m[!] ERROR : Mail İmap Login Başarısız 50 Deneme Yapıldı. \033[0m")
            return False

    time.sleep(50)
    folders = ["INBOX", "Junk"]
    res_code = ""
    for folder in folders:
        mail.select(folder)

        result, data = mail.search(None, "ALL")
        latest_email_id = data[0].split()[-1]
        result, data = mail.fetch(latest_email_id, "(RFC822)")

        raw_email = data[0][1]
        msg = email.message_from_bytes(raw_email)
        from_address = decode_header(msg["From"])[0][0]
        body = ""
        if msg.is_multipart():
            for part in msg.get_payload():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode()
        else:
            body = msg.get_payload(decode=True).decode()

        if "x.com" in from_address:
            pattern = re.compile(r'\b[0-9]{6}\b')
            res_code = pattern.search(body).group()
            break
    mail.close()
    mail.logout()
    if res_code:
        return res_code
    else:
        return "EC2"

def create_account(proxy_full,first_line):
    full_proxy = proxy_full.split("|")

    proxy = full_proxy[0]
    ip_reset = full_proxy[1]
    if first_line is None:
        with open("emails.txt", 'r') as file:
            lines = file.readlines()
        with open("emails.txt", 'w') as file:
            file.writelines(lines[1:])
        return

    emails_exp = first_line.split(":")
    use_email = emails_exp[0].strip()
    use_password = emails_exp[1].strip()
    use_imap_user = emails_exp[2].strip()
    use_imap_pass = emails_exp[3].strip()

    with open("emails.txt", 'r') as file:
        lines = file.readlines()
    with open("emails.txt", 'w') as file:
        file.writelines(lines[1:])

    used_emails_file = open("used_emails.txt", "a+")
    used_emails_file.write(first_line + "\n")
    used_emails_file.close()

    now = datetime.now()
    formatted_date = now.strftime("%d-%m-%Y")

    def get_context() -> SSLContext:
        context = create_ssl_context()
        cipher1 = "ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM:DH+CHACHA20:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:DH+HIGH:RSA+AESGCM:RSA+AES:RSA+HIGH"
        context.set_alpn_protocols(["h2"])
        context.set_ciphers(cipher1)
        return context

    if nameselec != "tr":
        rnd_male_nametr = (
            "Ziyad", "Zübeyr")
        rnd_women_nametr = (
            "Zeliha", "Zumrut")
        rnd_surnametr = (
            "Feyzullahoglu", "Şahi̇n")
        name = random.choice(rnd_women_nametr) + " " + random.choice(rnd_surnametr)
        birth_day = random.randint(1, 28)
        birth_mont = random.randint(1, 12)
        birth_year = random.randint(1970, 2002)

    else:
        rnd_male_namevn = (
            "wantanabe", "xuan")
        rnd_women_namevn = (
            "Pretty", "Xuyen")
        rnd_surnamevn = (
            "Vu", " Vuong")
        name = random.choice(rnd_women_namevn) + " " + random.choice(rnd_surnamevn)
        birth_day = random.randint(1, 28)
        birth_mont = random.randint(1, 12)
        birth_year = random.randint(1970, 2002)

    device_id, vendor_id, s_uuid = [str(uuid.uuid4()).upper() for _ in range(3)]

    def device_token() -> str:
        return "".join(
            secrets.choice(string.digits + string.ascii_lowercase + string.ascii_uppercase)
            for _ in range(40)
        )

    def trace_id() -> str:
        return "".join(
            secrets.choice(string.digits + string.digits + string.ascii_lowercase)
            for _ in range(16)
    )
    session = httpx.Client(
                http2=True,
                verify=get_context(),
                timeout=15,
                proxies=proxy,
    )
    now = datetime.now()
    dt_string = now.strftime("%H:%M:%S")
    if (ip_reset != ""):
        try:
            session.get(ip_reset)
            print("\033[1;33m[+] İP Reset kullanıldı 3 Saniye bekleniyor.\033[0m " + dt_string)
            time.sleep(5)
        except:
            print("[!] Mobile Proxy IP can't reset")
            return

    try:
        ip_response = session.get('https://api.ipify.org/')
        print("\033[1;33m[+] Using IP:\033[0m " + ip_response.text)
    except:
        fail_mail_file = open("fail_mail.txt", "a+")
        fail_mail_file.write(use_imap_user + ":" + use_imap_pass + "\n")
        fail_mail_file.close()
        print("\033[0;31m[!] ERROR : https://api.ipify.org/ \033[0m")
        return False

    gt_headers = {
               "host": "api.twitter.com",
               "content-type": "application/x-www-form-urlencoded",
               "x-twitter-client-deviceid": device_id,
               "accept": "application/json",
               "x-twitter-client-version": client_version,
               "authorization": f"Bearer {authorization}",
               "x-client-uuid": s_uuid,
               "x-twitter-client-language": accept_lang,
               "x-b3-traceid": trace_id(),
               "accept-language": accept_lang,
               "accept-encoding": "gzip, deflate, br",
               "user-agent": user_agent,
               "x-twitter-client-limit-ad-tracking": "0",
               "x-twitter-api-version": "5",
               "x-twitter-client": x_twitter_client,
    }
    if 'connection' in gt_headers:
        del gt_headers['connection']
    try:
        gt_response = session.post('https://api.twitter.com/1.1/guest/activate.json', headers=gt_headers)
        gt = gt_response.json().get("guest_token")
    except:
        fail_mail_file = open("fail_mail.txt", "a+")
        fail_mail_file.write(use_imap_user + ":" + use_imap_pass + "\n")
        fail_mail_file.close()
        print("\033[0;31m[!] ERROR : https://api.twitter.com/1.1/guest/activate.json \033[0m")
        return False
    if gt:
        print(f"\033[0;35m[+] Guest token:\033[0m {gt}")
    else:
        print("Failed grabbing guest token")
        return

    ift_headers = {
                'host': 'api.twitter.com',
                'user-agent': user_agent,
                'x-twitter-client': x_twitter_client,
                'x-twitter-client-deviceid': device_id,
                'twitter-display-size': display_size,
                'x-twitter-client-vendorid': vendor_id,
                'system-user-agent': system_user_agent,
                'x-twitter-client-version': client_version,
                'x-twitter-client-limit-ad-tracking': '0',
                'x-b3-traceid': trace_id(),
                'x-guest-token': gt,
                'accept-language': accept_lang,
                'authorization': f'Bearer {authorization}',
                'x-twitter-client-language': accept_lang,
                'x-client-uuid': s_uuid,
                'x-twitter-api-version': '5',
                'accept': 'application/json',
                'content-type': 'application/json',
                'os-version': r_os,
                'accept-encoding': 'gzip, deflate, br'
    }
    ift_response = session.post('https://api.twitter.com/1.1/onboarding/task.json?' + f'api_version=2&ext=highlightedLabel%2CmediaColor&flow_name=welcome&include_entities=1&include_profile_interstitial_type=true&include_profile_location=true&include_user_entities=true&include_user_hashtag_entities=true&include_user_mention_entities=true&include_user_symbol_entities=true&known_device_token={device_token}&sim_country_code=TR', headers=ift_headers, json=FLOW_INIT_PAYLOAD)
    ift = ift_response.json().get("flow_token")
    if ift:
        print(f"\033[0;35m[+] Flow token:\033[0m {ift}")
    else:
        print("Failed grabbing flow token")
        return
    def create_payload() -> dict:
            return {
                "clientKey": capsolver_api_key,
                "task": {
                    "type": "FunCaptchaTaskProxyLess",
                    "websiteURL": "https://mobile.twitter.com",
                    "websitePublicKey": "867D55F2-24FD-4C56-AB6D-589EDAF5E7C5",
                    "funcaptchaApiJSSubdomain": "https://client-api.arkoselabs.com",
                },
            }
    def solve_captcha() -> str:
            task_create = session.post(
                "https://api.capsolver.com/createTask",
                json=create_payload(),
            )
            task = task_create.json()
            if task.get("errorId", 1):
                print(
                    f"Error while creating task: {task['errorDescription']} {use_email}"
                )
            task_id = task["taskId"]
            task_results_payload = {"clientKey": capsolver_api_key, "taskId": task_id}

            get_task_results = session.post(
                "https://api.capsolver.com/getTaskResult",
                json=task_results_payload,
            )
            task_results = get_task_results.json()
            while task_results["status"] == "processing":
                task_results = session.post(
                    "https://api.capsolver.com/getTaskResult",
                    json=task_results_payload,
                ).json()
                time.sleep(2)
            if task_results["status"] == "error":
                print(
                    f"Error while solving task: {task_results['errorDescription']}"
                )
            return task_results["solution"]["token"]

    def basic_headers() -> Dict[str, str]:
        return {
            'host': 'api.twitter.com',
            'x-twitter-client-deviceid': device_id,
            'accept': 'application/json',
            'x-twitter-client-version': client_version,
            'x-guest-token': gt,
            'x-client-uuid': s_uuid,
            'x-twitter-client-language': accept_lang,
            'x-b3-traceid': trace_id(),
            'authorization': f'Bearer {authorization}',
            'accept-language': accept_lang,
            'user-agent': user_agent,
            'x-twitter-client-limit-ad-tracking': '0',
            'x-twitter-api-version': '5',
            'x-twitter-client': x_twitter_client,
        }
    def send_email_otp(email: str, flow_token: str) -> bool:
            otp_headers = {
                'host': 'api.twitter.com',
                'x-twitter-client-deviceid': device_id,
                'accept': 'application/json',
                'x-twitter-client-version': client_version,
                'x-guest-token': gt,
                'x-client-uuid': s_uuid,
                'x-twitter-client-language': accept_lang,
                'x-b3-traceid': trace_id(),
                'authorization': f'Bearer {authorization}',
                'accept-language': accept_lang,
                'user-agent': user_agent,
                'x-twitter-client-limit-ad-tracking': '0',
                'x-twitter-api-version': '5',
                'x-twitter-client': x_twitter_client
            }
            otp_payload = {
                "email": email,
                "display_name": name.replace(" ", ""),
                "flow_token": flow_token,
                "use_voice": "false",
            }
            otp_response = session.post(
                "https://api.twitter.com/1.1/onboarding/begin_verification.json",
                json=otp_payload,
                headers=otp_headers,
            )
            return otp_response.status_code == 204
    def email_code_flow(email: str, otp_code: str, flow_token: str, js_instrumentation: str, captcha_key: str) -> str:
            code_headers = {
                'host': 'api.twitter.com',
                'user-agent': user_agent,
                'x-twitter-client': x_twitter_client,
                'x-twitter-client-deviceid': device_id,
                'x-guest-token': gt,
                'twitter-display-size': display_size,
                'x-twitter-client-vendorid': vendor_id,
                'system-user-agent': system_user_agent,
                'x-twitter-client-version': client_version,
                'x-twitter-client-limit-ad-tracking': '0',
                'x-b3-traceid': trace_id(),
                'accept-language': accept_lang,
                'authorization': f'Bearer {authorization}',
                'x-twitter-client-language': accept_lang,
                'x-client-uuid': s_uuid,
                'x-twitter-api-version': '5',
                'accept': 'application/json',
                'content-type': 'application/json',
                'os-version': r_os,
            }

            code_payload = {
                "flow_token": flow_token,
                "subtask_inputs": [
                    {
                        "subtask_id": "SplashScreenWithSso",
                        "cta": {
                            "link": "signup",
                            "component_values": []
                        }
                    },
                    {
                        "subtask_id": "WelcomeFlowStartSignupOpenLink",
                        "open_link": {
                            "link": "welcome_flow_start_signup",
                            "component_values": []
                        }
                    },
                    {
                        "subtask_id": "Signup",
                        "sign_up": {
                            "email": email,
                            "js_instrumentation": {
                                "response": js_instrumentation
                            },
                            "name": name,
                            "birthday": {
                                "year": birth_year,
                                "month": birth_mont,
                                "day": birth_day
                            },
                            "link": "email_next_link"
                        }
                    },
                    {"subtask_id":"ArkoseEmail","web_modal":{"completion_deeplink":"twitter://onboarding/web_modal/next_link?access_token="+ captcha_key + "","link":"signup_with_email_next_link"}},
                    {
                        "subtask_id": "SignupSettingsListEmailNonEU",
                        "settings_list": {
                            "link": "next_link",
                            "component_values": [],
                            "setting_responses": [
                                {
                                    "key": "twitter_for_web",
                                    "response_data": {
                                        "boolean_data": {
                                            "result": 'false'
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "subtask_id": "SignupReview",
                        "sign_up_review": {
                            "link": "signup_with_email_next_link",
                            "component_values": []
                        }
                    },
                    {
                        "subtask_id": "EmailVerification",
                        "email_verification": {
                            "code": otp_code,
                            "component_values": [],
                            "email": email,
                            "link": "next_link"
                        }
                    }
                ]
            }

            code_response = session.post(
                "https://api.twitter.com/1.1/onboarding/task.json?ext=highlightedLabel%2CmediaColor&include_entities=1&include_profile_interstitial_type=true&include_profile_location=true&include_user_entities=true&include_user_hashtag_entities=true&include_user_mention_entities=true&include_user_symbol_entities=true",
                json=code_payload,
                headers=code_headers,
            )

            jsn = code_response.json()
            if jsn.get("status", "") == "success":
                return jsn["flow_token"]
            else:
                print(f"Error while Completing email flow: {jsn} {use_email}")
                fail_mail_file = open("fail_mail.txt", "a+")
                fail_mail_file.write(use_imap_user + ":" + use_imap_pass + "\n")
                fail_mail_file.close()
                return False

    def password_flow(flow_token: str, password: str) -> str:

            global auth_kdt
            global oauth_token
            global oauth_secret

            pf_headers = {
                'host': 'api.twitter.com',
                'user-agent': user_agent,
                'x-twitter-client': x_twitter_client,
                'x-twitter-client-deviceid': device_id,
                'x-guest-token': gt,
                'twitter-display-size': display_size,
                'x-twitter-client-vendorid': vendor_id,
                'system-user-agent': system_user_agent,
                'x-twitter-client-version': client_version,
                'x-twitter-client-limit-ad-tracking': '0',
                'x-b3-traceid': trace_id(),
                'accept-language': accept_lang,
                'authorization': f'Bearer {authorization}',
                'x-twitter-client-language': accept_lang,
                'x-client-uuid': s_uuid,
                'x-twitter-api-version': '5',
                'accept': 'application/json',
                'content-type': 'application/json',
                'os-version': r_os,
            }
            pf_payload = {
                "flow_token": flow_token,
                "subtask_inputs": [
                    {
                        "subtask_id": "EnterPassword",
                        "enter_password": {
                            "link": "next_link",
                            "component_values": [],
                            "password": password
                        }
                    }
                ]
            }

            pf_response = session.post(
                "https://api.twitter.com/1.1/onboarding/task.json?ext=highlightedLabel%2CmediaColor&include_entities=1&include_profile_interstitial_type=true&include_profile_location=true&include_user_entities=true&include_user_hashtag_entities=true&include_user_mention_entities=true&include_user_symbol_entities=true",
                json=pf_payload,
                headers=pf_headers,
            )
            jsn = pf_response.json()
            if jsn.get("status", "") == "success":
                print("\033[1;33m[+] Completed password flow\033[0m")
                auth_kdt = pf_response.headers.get("kdt", "")
                oauth_token = jsn["subtasks"][0]["open_account"]["oauth_token"]
                oauth_secret = jsn["subtasks"][0]["open_account"][
                    "oauth_token_secret"
                ]
                return jsn["flow_token"]
            else:
                print(f"Error while filling out password flow: {jsn}")
                return False
    def solve_instrumentation(data: str) -> str:
        LIBRARY.parseScript.argtypes = [ctypes.c_char_p]
        LIBRARY.parseScript.restype = ctypes.c_char_p

        data = data.encode("utf-8")
        response = LIBRARY.parseScript(data)
        return response.decode()
    def get_web_instrumentation() -> str:
        xsession = requests.Session()
        data = xsession.get(
            'https://twitter.com/i/js_inst?c_name=ui_metrics',
            headers={
                "accept": "*/*",
                "Referer": "https://twitter.com/i/flow/signup",
                "Sec-Fetch-Dest": "script",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "same-origin"
            }
        )
        return solve_instrumentation(data.text)
    def init_session(token: str) -> Client:
            x_session = Client(
                proxies=proxy,
                timeout=30
            )
            x_session.cookies["auth_token"] = token
            _get_cookies(session)
            return session


    def getAuth(method, url, secret, token, params):
        client = oauth1.Client(
            "IQKbtAYlXLripLGPWd0HUA",
            client_secret="GgDYlkSvaPxGxC4X8liwpUoqKwwr3lCADbz8A7ADU",
            resource_owner_key=token,
            resource_owner_secret=secret,
            signature_method=oauth1.SIGNATURE_HMAC_SHA1,
        )

        if params is None:
            params = GENERAL_PARAMS
            enc = urlencode(params)
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            _, headers, _ = client.sign(url, http_method=method, headers=headers, body=enc)
            return headers["Authorization"]
        if params == "NO_VALUE":
            _, headers, _ = client.sign(url, http_method=method)
            return headers["Authorization"]
        enc = urlencode(params)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        _, headers, _ = client.sign(url, http_method=method, headers=headers, body=enc)
        return headers["Authorization"]
    def _get_cookies(session: Client) -> None:
            try:
                session.headers = {
                    "authority": "twitter.com",
                    "accept": "*/*",
                    "accept-language": m_accept_lang,
                    "authorization": "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
                    "content-type": "application/json",
                    "referer": "https://twitter.com/",
                    "sec-ch-ua": '"Not/A)Brand";v="99", "Brave";v="120", "Chromium";v="120"',
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": '"Windows"',
                    "sec-fetch-dest": "empty",
                    "sec-fetch-mode": "cors",
                    "sec-fetch-site": "same-origin",
                    "sec-gpc": "1",
                    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "x-client-transaction-id": "k5EGS2Mu/OnX/xGtwHtqbZ8/euSDYZUWpn/44FpzElhoSbuNTCnfFpcK+ajyPP/491pZHpMbTSnGQtiP7O5YuwjO74Hikg",
                    "x-client-uuid": str(uuid4()),
                    "x-twitter-active-user": "yes",
                    "x-twitter-auth-type": "OAuth2Session",
                    "x-twitter-client-language": accept_lang,
                }
                session.post(
                    "https://twitter.com/i/api/1.1/account/update_profile.json"
                )
                session.headers["x-csrf-token"] = session.cookies.get("ct0")
            except TimeoutError:
                return

    def get_token() -> str:

            url = "https://api-31-0-0.twitter.com/1.1/account/settings.json?include_alt_text_compose=true&include_ext_dm_nsfw_media_filter=true&include_ext_re_upload_address_book_time=true&include_ext_sharing_audiospaces_listening_data_with_followers=true&include_ext_sso_connections=true&include_mention_filter=true&include_nsfw_admin_flag=true&include_nsfw_user_flag=true&include_universal_quality_filtering=true&protected=false"

            headers = {
                "host": "api-31-0-0.twitter.com",
                "kdt": auth_kdt,
                "user-agent": user_agent,
                "x-twitter-client": x_twitter_client,
                "x-twitter-client-deviceid": device_id,
                "x-twitter-active-user": "yes",
                "twitter-display-size": display_size,
                "x-twitter-client-vendorid": vendor_id,
                "system-user-agent": system_user_agent,
                "x-twitter-client-version": client_version,
                "x-twitter-client-limit-ad-tracking": "0",
                "x-b3-traceid": trace_id(),
                "accept-language": accept_lang,
                "timezone": "",
                "authorization": getAuth(
                    "POST",
                    url,
                    oauth_secret,
                    oauth_token,
                    "NO_VALUE",
                ),
                "x-twitter-client-language": accept_lang,
                "x-client-uuid": s_uuid,
                "x-twitter-api-version": "5",
                "accept": "application/json",
                "content-type": "application/json",
                "os-version": r_os,
            }
            rrs = session.post(url, headers=headers)
            url = "https://twitter.com/account/authenticate_web_view?redirect_url=https%3A%2F%2Fhelp.twitter.com%2F"

            headers = {
                "host": "twitter.com",
                "kdt": auth_kdt,
                "user-agent": user_agent,
                "x-twitter-client": x_twitter_client,
                "x-twitter-client-deviceid": device_id,
                "x-twitter-active-user": "yes",
                "twitter-display-size": display_size,
                "x-twitter-client-vendorid": vendor_id,
                "system-user-agent": system_user_agent,
                "x-twitter-client-version": client_version,
                "x-twitter-client-limit-ad-tracking": "0",
                "x-b3-traceid": trace_id(),
                "accept-language": accept_lang,
                "timezone": "",
                "authorization": getAuth(
                    "GET",
                    url,
                    oauth_secret,
                    oauth_token,
                    "NO_VALUE",
                ),
                "x-twitter-client-language": accept_lang,
                "x-client-uuid": s_uuid,
                "x-twitter-api-version": "5",
                "accept": "application/json",
                "content-type": "application/json",
                "os-version": r_os,
            }
            r = session.get(url, headers=headers)
            return r.cookies["auth_token"]

    def getuser():

        url = "https://api.twitter.com/1.1/account/verify_credentials.json"

        headers = {
            "host": "api.twitter.com",
            "kdt": auth_kdt,
            "user-agent": user_agent,
            "x-twitter-client": x_twitter_client,
            "x-twitter-client-deviceid": device_id,
            "x-twitter-active-user": "yes",
            "twitter-display-size": display_size,
            "x-twitter-client-vendorid": vendor_id,
            "system-user-agent": system_user_agent,
            "x-twitter-client-version": client_version,
            "x-twitter-client-limit-ad-tracking": "0",
            "x-b3-traceid": trace_id(),
            "accept-language": accept_lang,
            "timezone": "",
            "authorization": getAuth(
                "GET",
                url,
                oauth_secret,
                oauth_token,
                "NO_VALUE",
            ),
            "x-twitter-client-language": accept_lang,
            "x-client-uuid": s_uuid,
            "x-twitter-api-version": "5",
            "accept": "application/json",
            "content-type": "application/json",
            "os-version": r_os,
        }

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            user_info = response.json()
            return user_info['screen_name']
        else:
            print('Invalid credentials')

    def save_account(account: str, path: str = None) -> None:
            if path is None:
                path = "accounts.txt"
            with open(path, "a", encoding="utf-8") as file:
                    file.write(f"{account}\n")

    if use_imap != "y":
        try:
            with rent_email() as (activation_id, email):
                chkimap = check_imap(use_imap_user, use_imap_user)
                if chkimap == 0:
                    print("\033[0;31m[!] Failed to access IMAP\033[0m")
                    return
                password = secrets.token_urlsafe(10)
                print(f"\033[1;33m[+] Email rented:\033[0m {email}")
                try:
                    captcha_key = solve_captcha()
                    print(f"\033[1;33m[+] Captcha solved:\033[0m {captcha_key[:12]}")
                except:
                    print("\033[0;31m[!] Captcha can't solved\033[0m")
                    fail_mail_file = open("fail_mail.txt", "a+")
                    fail_mail_file.write(use_imap_user + ":" + use_imap_pass + "\n")
                    fail_mail_file.close()
                    return
                sent_otp = send_email_otp(email, ift)
                if not sent_otp:
                    print("\033[0;31m[!] Failed to send email OTP\033[0m")
                    return
                print(f"\033[1;33m[+] OTP Code Sent:\033[0m {sent_otp}")

                email_code = get_code(activation_id)
                if not email_code:
                    print("\033[0;31m[!] Failed to get email code, canceling email\033[0m")
                    cancel_email(activation_id)
                    return
                print(f"\033[1;33m[+] Email code received:\033[0m {email_code}")

                js_instrumentation = get_web_instrumentation()
                #print(f"[+] JS Data: {str(js_instrumentation)[:12]}")
                second_token = email_code_flow(email, email_code, ift, js_instrumentation, captcha_key)
                if second_token is False:
                    print("\033[0;31m[!] Failed to get email flow\033[0m")
                    fail_mail_file = open("fail_mail.txt", "a+")
                    fail_mail_file.write(use_imap_user + ":" + use_imap_pass + "\n")
                    fail_mail_file.close()
                    time.sleep(15)
                    return
                print("\033[1;33m[+] Completed email flow\033[0m")
                time.sleep(1)
                cflow = password_flow(second_token, password)
                if cflow is False:
                    print("\033[0;31m[!] Failed to get password flow\033[0m")
                    fail_mail_file = open("fail_mail.txt", "a+")
                    fail_mail_file.write(use_imap_user + ":" + use_imap_pass + "\n")
                    fail_mail_file.close()
                    return
                username = getuser()
                auth_token = get_token()
                session = init_session(auth_token)
                print(f"\033[1;32m[+] Account created:\033[0m {username}")
                save_account(f"{username}:{email}:{password}:{session.cookies.get('ct0', '')}:{auth_token}:{formatted_date}")
                return
        except Exception as e:
            fail_mail_file = open("sll_error.txt", "a+")
            fail_mail_file.write(use_imap_user + ":" + use_imap_pass + "\n")
            fail_mail_file.close()
            print(f"[!] Error: \033[0;31m{e}\033[0m")
    else:
        try:
                password = use_password
                print(f"\033[1;33m[+] Email using:\033[0m {use_email}")
                try:
                    captcha_key = solve_captcha()
                    print(f"\033[1;33m[+] Captcha solved:\033[0m {captcha_key[:12]}")
                except:
                    print("\033[0;31m[!] Captcha can't solved\033[0m")
                    fail_mail_file = open("fail_mail.txt", "a+")
                    fail_mail_file.write(use_imap_user + ":" + use_imap_pass + "\n")
                    fail_mail_file.close()
                    return
                sent_otp = send_email_otp(use_email, ift)
                if not sent_otp:
                    print("\033[0;31m[!] Failed to send email OTP\033[0m")
                    return
                print(f"\033[1;33m[+] OTP Code Sent:\033[0m {sent_otp}")

                try:
                    email_code = check_email(use_imap_user, use_imap_pass)
                except:
                    print(f"\033[1;31m[!] Failed to get email code\033[0m {use_email}")
                    print(f"Error while Completing email flow: {use_email}")
                    fail_mailcode_file = open("fail_mailcode.txt", "a+")
                    fail_mailcode_file.write(use_imap_user + ":" + use_imap_pass + "\n")
                    fail_mailcode_file.close()
                    time.sleep(15)
                    return
                if email_code != "EC2":
                    print(f"\033[1;33m[+] Email code received:\033[0m {email_code}")
                else:
                    print(f"\033[1;31m[!] Failed to get email code\033[0m {use_email}")
                    fail_mailcode_file = open("fail_mailcode.txt", "a+")
                    fail_mailcode_file.write(use_imap_user + ":" + use_imap_pass + "\n")
                    fail_mailcode_file.close()
                    time.sleep(10)
                    return

                js_instrumentation = get_web_instrumentation()
                second_token = email_code_flow(use_email, email_code, ift, js_instrumentation, captcha_key)
                if second_token is False:
                    print("\033[0;31m[!] Failed to get email flow\033[0m")
                    fail_mail_file = open("fail_mail.txt", "a+")
                    fail_mail_file.write(use_imap_user + ":" + use_imap_pass + "\n")
                    fail_mail_file.close()
                    time.sleep(15)
                    return
                print("\033[1;33m[+] Completed email flow\033[0m")
                time.sleep(0.5)
                cflow = password_flow(second_token, password)
                if cflow is False:

                    print("\033[0;31m[!] Failed to get password flow\033[0m")
                    fail_mail_file = open("fail_mail.txt", "a+")
                    fail_mail_file.write(use_imap_user + ":" + use_imap_pass + "\n")
                    fail_mail_file.close()
                    time.sleep(10)
                    return
                username = getuser()
                auth_token = get_token()
                session = init_session(auth_token)
                print(f"\033[1;32m[+] Account created:\033[0m {username}")
                save_account(f"{username}:{password}:{use_email}:{use_password}:{session.cookies.get('ct0', '')}:{auth_token}:{formatted_date}:{use_imap_user}:{use_imap_pass}")
                time.sleep(5)
                return
        except Exception as e:
            fail_mail_file = open("sll_error.txt", "a+")
            fail_mail_file.write(use_imap_user + ":" + use_imap_pass + "\n")
            fail_mail_file.close()
            print(f"[!] Error: \033[0;31m{e}\033[0m")
"""
while True:
    threads = []

    for i in range(run_threads):
        with open("emails.txt", 'r') as ffile:
            first_line = ffile.readline().strip()
            if not first_line:
                print("emails.txt is empty. Stopping the process.")
                break
        thread = threading.Thread(target=create_account, args=(first_line,))
        threads.append(thread)
        thread.start()
        time.sleep(1)

    for thread in threads:
        thread.join()
"""
while (True):
    with open('mobile-proxies.txt', 'r') as file:
        threads = []
        for line in file:
            with open("emails.txt", 'r') as ffile:
                first_line = ffile.readline()
            proxy_full = line.strip()
            thread = threading.Thread(target=create_account, args=(proxy_full, first_line,))
            threads.append(thread)
            thread.start()
            time.sleep(1)

        for thread in threads:
            thread.join()
