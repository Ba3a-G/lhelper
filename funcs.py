import re
import aiohttp
import json
import boto3
from boto3.dynamodb.conditions import Key
from datetime import datetime as t
from config import *
import time

dynamodb = boto3.resource(
    'dynamodb',
    aws_access_key_id=access_key_id,
    aws_secret_access_key=access_key_token,
    region_name='us-east-1')


''' Login V2
Here is what this script does
    0. Reauth cookie
        01 Get profile from database
        02 If profle exists and pass matches and cookie exists, do cookie reauth and skip 1
        03 Else do 1

    1. Validates password
        11. If fails returns error
        12. If passes returns access token, jwt as an object called headers

    2. Update profile
        21. If all profile data don't match or DNE, PUT's Profile
        22. Else, does nothing
        
    3. Refreshes store
        31. If store data expired or DNE, PUT's store data
'''

async def queryDB(table, username, key):
    response = dynamodb.Table(table).query(
        KeyConditionExpression=Key('rito_username').eq(username)
    )
    if response['Items']:
        return response['Items'][0][key]
    else:
        return None



async def validatePass(username, password, session, pattern):
    data = {
        "client_id": "play-valorant-web-prod",
        "nonce": "1",
        "redirect_uri": "https://playvalorant.com/opt_in",
        "response_type": "token id_token",
        "response_mode": "query",
        "scope": "account openid"
    }
    headers = {
        'User-Agent': 'RiotClient/51.0.0.4429735.4381201 rso-auth (Windows;10;;Professional, x64)'
    }
    await session.post('https://auth.riotgames.com/api/v1/authorization', json=data, headers=headers)

    data = {
        'type': 'auth',
        'username': username,
        'password': password
    }
    if 'https://' not in password:
        async with session.put('https://auth.riotgames.com/api/v1/authorization', json=data, headers=headers) as r:
            data = await r.json()       
    else:
        async with session.get(password) as r:
            data = await r.json()
    
    if data['type'] == 'multifactor':
        print("2FA enabled. Please enter code.")
        return 'multifactor', None
    elif 'error' in data and data['error'] == 'auth_failure':
        print("Wrong Pass")
        return 'auth_failure', None
    
    data = pattern.findall(data['response']['parameters']['uri'])[0]
    access_token = data[0]
    filtered = session.cookie_jar.filter_cookies('https://auth.riotgames.com/')
    newCookie = str(filtered['ssid']).split('=')[1]
    #returns access token, cookie
    return access_token, newCookie

async def submitCode(username, code, session, pattern):
    data = {"type": "multifactor", "code": code, "rememberDevice": True}
    headers = {
        'User-Agent': 'RiotClient/43.0.1.4195386.4190634 rso-auth (Windows;10;;Professional, x64)'
    }
    async with session.post('https://auth.riotgames.com/api/v1/authorization', json=data, headers=headers) as r:
        data = await r.json()
    try:
        data = pattern.findall(data['response']['parameters']['uri'])[0]
        access_token = data[0]
        rawCookie = session.cookie_jar.filter_cookies('https://auth.riotgames.com/')
        newCookie = ""
        for each in rawCookie:          
            newCookie += str(rawCookie[each]).split(" ")[1]+ "; "
    except Exception as e:
        print(e)
        return "MFA code error", None
    return access_token, newCookie

async def getJWT(access_token, session):   
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    async with session.post('https://entitlements.auth.riotgames.com/api/token/v1', headers=headers, json={}) as r:
        data = await r.json()
    jwt = data['entitlements_token']
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'X-Riot-Entitlements-JWT': jwt
    }
    
    #returns access token and jwt in an object called headers
    return headers

async def updateDB(table, username, key, oldData, newData):
    if oldData == newData:
            return
    else:
        dynamodb.Table(table).update_item(
            Key={'rito_username': username},
            AttributeUpdates= {
                key: {'Action':'PUT','Value': newData},
                },
            )
    
async def refreshProfile(username, password, region, headers, session, cookie, profile):
    #updates the user profile (username, pass, valoid, region) if all data don't match
    #creates new entry if 404
    #returns user_id
    
    if profile['Count'] == 0:
        async with session.post('https://auth.riotgames.com/userinfo', headers=headers, json={}) as r:
            data = await r.json()
        user_id = data['sub']
        print('profile DNE. Creating New')
        dynamodb.Table('valstore_accounts').update_item(
          Key={'rito_username': username},
          AttributeUpdates= {
            'rito_password': {'Action':'PUT','Value':password},
            'rito_id': {'Action':'PUT','Value':user_id},
            'region': {'Action':'PUT','Value':region},
            'cookie': {'Action':'PUT','Value':cookie},
            },
        )

    else:
        await updateDB('valstore_accounts', username, 'rito_password', profile['Items'][0]['rito_password'], password)
        try:
            await updateDB('valstore_accounts', username, 'cookie', profile['Items'][0]['cookie'], cookie)
        except:
            await updateDB('valstore_accounts', username, 'cookie', None, cookie)
        user_id = profile['Items'][0]['rito_id']

    print('Set user ID as:'+ user_id)
    return user_id
    
    
async def refreshStore(username, user_id, region, headers, session):
    #get store data
    time_now = int(t.now().timestamp())
    store = dynamodb.Table('valstore_daily_store').query(KeyConditionExpression=Key('rito_username').eq(username))
    if store['Count'] == 0 or time_now-int(store['Items'][0]['expires'])>0:
        async with session.get(f'https://pd.{region}.a.pvp.net/store/v2/storefront/{user_id}', headers=headers) as r:
            data = await r.json()
        
        tempskins = {
            'rito_username': username,
            'rito_id': user_id,
            'last_updated': str(time_now),
            'expires': str(time_now+data['SkinsPanelLayout']['SingleItemOffersRemainingDurationInSeconds']),
            'status': 'live',
            'weaponskins': {"1": {},"2": {},"3":{},"4": {}}
        }
        n=1
        for i in data['SkinsPanelLayout']['SingleItemOffers']:
            skin = dynamodb.Table('valstore_skins_data').query(KeyConditionExpression=Key('skin_id').eq(i))
            tempskins['weaponskins'][str(n)]['name'] = skin['Items'][0]['skin_name']
            tempskins['weaponskins'][str(n)]['image'] = skin['Items'][0]['skin_image']
            tempskins['weaponskins'][str(n)]['video'] = skin['Items'][0]['skin_video']
            tempskins['weaponskins'][str(n)]['price'] = skin['Items'][0]['skin_price']
            n+=1

        #PUT tempskins to db here
        dynamodb.Table('valstore_daily_store').put_item(Item=tempskins)        
            
    else:
        print('store not updated')