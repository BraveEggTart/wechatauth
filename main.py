import os
import base64
import logging
import json
import time
import random
import string
import hashlib
import requests
from datetime import datetime, timedelta
from copy import deepcopy

import uvicorn
from Crypto.Cipher import AES
from dotenv import load_dotenv
from fastapi import FastAPI, APIRouter
from fastapi.responses import HTMLResponse

load_dotenv()
app = FastAPI()
logger = logging.getLogger(__name__)
router = APIRouter()
WINXIN_TOKEN: str = os.getenv("TOKEN", "")
APP_ID: str = os.getenv("APPID", "")
SECRET: str = os.getenv("SECRET", "")
# 初始化缓存和时间戳
cache = {
    "access_token": None,
    "jsapi_ticket": None,
    "nonceStr": None,
    "call_time": datetime.now()-timedelta(hours=3),
    "timestamp": None,
    "signature": None,
}
site_cache = {}


def create_noncestr(length=16):
    """生成随机字符串"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def create_timestamp():
    """生成时间戳"""
    return int(time.time())


def get_access_token():
    global cache
    # 检查是否超过2小时
    if datetime.now() - cache["call_time"] > timedelta(hours=1.9):
        url = "https://api.weixin.qq.com/cgi-bin/token"
        params = {
            "grant_type": "client_credential",
            "appid": APP_ID,
            "secret": SECRET,
        }
        total_url = "?".join([
            url,
            '&'.join(f'{k}={v}' for k, v in params.items())
        ])
        response = requests.get(
            url=total_url,
            json=params
        ).json()
        cache["access_token"] = response["access_token"]
    return cache["access_token"]


def get_jsapi_ticket():
    global cache
    # 检查是否超过2小时
    if datetime.now() - cache["call_time"] > timedelta(hours=1.9):
        access_token = get_access_token()
        url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket"
        params = {
            "access_token": access_token,
            "type": "jsapi",
        }
        total_url = "?".join([
            url,
            '&'.join(f'{k}={v}' for k, v in params.items())
        ])
        response = requests.get(
            url=total_url,
            json=params
        ).json()
        cache["jsapi_ticket"] = response["ticket"]
    return cache["jsapi_ticket"]


def create_signature(share_url):
    """生成签名"""
    noncestr = create_noncestr()
    timestamp = create_timestamp()
    jsapi_ticket = get_jsapi_ticket()

    # 将参数按照字段名的ASCII 码从小到大排序
    params = {
        'noncestr': noncestr,
        'jsapi_ticket': jsapi_ticket,
        'timestamp': timestamp,
        'url': share_url,
    }
    sorted_params = sorted(params.items())

    # 使用URL键值对的格式拼接成字符串
    _ = '&'.join(f'{k}={v}' for k, v in sorted_params)
    print("string1 = ", _)
    print("jsapi_ticket = ", jsapi_ticket)
    print("share_url = ", share_url)
    print("noncestr = ", noncestr)
    print("timestamp = ", timestamp)
    # 使用sha1加密
    signature = hashlib.sha1(_.encode('utf-8')).hexdigest()

    return noncestr, timestamp, signature


@app.get(
    "/",
    tags=["验证服务器地址的有效性"],
)
async def check_signature(
        signature: str,
        echostr: str,
        timestamp: str,
        nonce: str
):
    """
    signature 微信加密签名,signature结合了开发者填写的token参数和请求中的timestamp参数、nonce参数。
    timestamp 时间戳
    nonce 随机数
    echostr 随机字符串

    开发者通过检验signature对请求进行校验(下面有校验方式)。
    若确认此次GET请求来自微信服务器,请原样返回echostr参数内容,则接入生效,成为开发者成功,否则接入失败。
    加密/校验流程如下:
        1)将token、timestamp、nonce三个参数进行字典序排序
        2)将三个参数字符串拼接成一个字符串进行sha1加密
        3)开发者获得加密后的字符串可与signature对比,标识该请求来源于微信
    """
    _ = "".join(sorted([WINXIN_TOKEN, timestamp, nonce]))
    sign = hashlib.sha1(_.encode('UTF-8')).hexdigest()
    return HTMLResponse(content=echostr if sign == signature else "error")


@app.get(
    "/share/",
    tags=["生成分享验证密钥"],
)
async def generate_signature(url: str):
    """
    1.获取access_token(有效期7200秒,开发者必须在自己的服务全局缓存access_token)
    2.使用access_token获得jsapi_ticket(有效期7200秒,开发者必须在自己的服务全局缓存jsapi_ticket)

    签名生成规则如下:
        参与签名的字段包括noncestr(随机字符串), 有效的jsapi_ticket, timestamp(时间戳), 
        url(当前网页的URL,不包含#及其后面部分) 。
        1) 对所有待签名参数按照字段名的ASCII码从小到大排序(字典序)后,
        2) 使用URL键值对的格式(即key1=value1&key2=value2…)拼接成字符串。这里需要注意的是所有参数名均为小写字符。
        3) 对字符串作sha1加密, 字段名和字段值都采用原始值, 不进行URL转义。
    """
    global cache
    global site_cache
    if (
        datetime.now() - site_cache.get(
            url, {}
        ).get(
            "call_time", datetime.now() - timedelta(hours=3)
        ) > timedelta(hours=1.9)
    ):
        # 直接生成
        nonceStr, timestamp, signature = create_signature(url)
        cache["nonceStr"] = nonceStr
        cache["timestamp"] = timestamp
        cache["signature"] = signature
        cache["call_time"] = datetime.now()
        cache["url"] = url
        site_cache[url] = deepcopy(cache)
    print(str(site_cache[url]))
    return {
        "code": 0,
        "APP_ID": APP_ID,
        "nonceStr": site_cache[url]["nonceStr"],
        "timestamp": site_cache[url]["timestamp"],
        "signature": site_cache[url]["signature"],
    }


class WXBizDataCrypt:
    def __init__(self, appId, sessionKey):
        self.appId = appId
        self.sessionKey = sessionKey

    def decrypt(self, encryptedData, iv):
        # base64 decode
        sessionKey = base64.b64decode(self.sessionKey)
        encryptedData = base64.b64decode(encryptedData)
        iv = base64.b64decode(iv)

        cipher = AES.new(sessionKey, AES.MODE_CBC, iv)

        decrypted = json.loads(self._unpad(cipher.decrypt(encryptedData)))

        if decrypted['watermark']['appid'] != self.appId:
            raise Exception('Invalid Buffer')

        return decrypted

    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]


# 解密获取用户信息
def decrypt_encrypteddata(session_key, encryptedData, iv):
    decrypt_data = WXBizDataCrypt(APP_ID, session_key)
    decrypt_data = decrypt_data.decrypt(encryptedData, iv)
    return decrypt_data


# 登录接口
@router.get(
    "/login"
)
async def wx_login(
    # encryptedData: str,
    # iv: str,
    code: str,
):
    """
    通过参数APPID, SECRET, js_code获取到用户的微信唯一标识openID和sessionKey
    通过参数encryptedData 、iv 、sessionKey 请求后台解密获取用户信息
    :param request_data: 请求参数包含encryptedData，iv，code
    :return:
    """
    try:
        res = requests.get(
            url="https://api.weixin.qq.com/sns/jscode2session",
            params={
                "appid": APP_ID,
                "secret": SECRET,
                "js_code": code,
                "grant_type": "authorization_code",
            }
        )
        res = res.json()
        print(res)
        # {'session_key': 'xx', 'openid': 'xx'}
        if "session_key" in res:
            # user_info = decrypt_encrypteddata(res['session_key'], encryptedData, iv)
            return "登陆成功"
        else:
            return res
    except Exception as e:
        return str(e)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8444, reload=True)