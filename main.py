from discord.ext import commands
from discord.commands import Option
from config import *

import aiohttp
import asyncio
from funcs import *

bot = commands.Bot(prefix=commands.when_mentioned_or(">>"))




async def checkAuthorisation(ctx, username):
    #if queryDB('valstore_MFA_auth', username, 'mfa_auth')['Count'] == 0:
    #    await ctx.send('You are not authorized to use this command. Please contact a moderator.')
    #    return False
    return True

@bot.event
async def on_ready():
    print("Logged in as " + bot.user.name)



@bot.slash_command(guild_ids=[989384073455738930], description="Login to Valorant with Multi Factor Authentication")
async def login(ctx,
    username:Option(str, "Username"),
    password:Option(str, "Password"),
    region:Option(str, "Region",
    choices = ['NA', 'AP', 'EU', 'KR'])):
    await ctx.respond('Logging in...', ephemeral=True)

    def check(msg):
        return msg.author == ctx.author and msg.channel == ctx.channel and \
        msg.content.is_digit() and len(str(msg.content)) == 6

    access = await checkAuthorisation(ctx, username)
    if access == False:
        return
    try:
        session = aiohttp.ClientSession()
        pattern = re.compile('access_token=((?:[a-zA-Z]|\d|\.|-|_)*).*id_token=((?:[a-zA-Z]|\d|\.|-|_)*).*expires_in=(\d*)')
        access_token, newCookie = await validatePass(username, password, session, pattern)
        if access_token == "multifactor":
            code = await ctx.wait_for("Please enter the 6 digit 2FA code: ", check=check, timeout=120)
            access_token, newCookie = await submitCode(username, code, session, pattern)
        if newCookie != None:
            headers = await getJWT(access_token, session)
            userProfile = dynamodb.Table('valstore_accounts').query(KeyConditionExpression=Key('rito_username').eq(username))
            userID = await refreshProfile(username, password, region.lower(), headers, session, newCookie, userProfile)
            x= await refreshStore(username, userID, region, headers, session)
            await ctx.respond('Login successful!  You can now view your store on https://valostore.esportsforum.co.in/.')
        elif access_token == "auth_failure":
            await ctx.respond('Login failed. Please check your credentials.')
    except asyncio.TimeoutError:
        await ctx.respond('Login timed out. Please try again later.')
    except Exception as e:
        print(e)
        await ctx.respond('Some error occured.')



bot.run(discordToken)