import discord
from discord.commands import Option
from discord.ext import commands
from discord.ui import InputText, Modal
from config import *

import aiohttp
import asyncio
from funcs import *


class Bot(commands.Bot):
    def __init__(self):
        super().__init__(command_prefix=">")


bot = Bot()


class MyModal(Modal):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.add_item(InputText(label="Enter code", placeholder="sent to you by email"))

    async def callback(self, interaction: discord.Interaction):
        code = self.children[0].value
        print(code)
        access_token, newCookie = await submitCode(self.username, code, self.session, self.pattern)
        print(access_token)
        headers = await getJWT(access_token, self.session)
        userProfile = dynamodb.Table('valstore_accounts').query(KeyConditionExpression=Key('rito_username').eq(self.username))
        userID = await refreshProfile(self.username, self.password, self.region.lower(), headers, self.session, newCookie, userProfile)
        x = await refreshStore(self.username, userID, self.region, headers, self.session)

        embed = discord.Embed(title="Login Successfull", color=discord.Color.random())
        embed.add_field(name="Username: ", value=self.username, inline=True)
        embed.add_field(name="Check you store here: ", value="https://valostore.esportsforum.co.in", inline=False)
        await interaction.response.send_message(embeds=[embed])


@bot.event
async def on_ready():
    print("Logged in as " + bot.user.name)

@bot.slash_command(name="login", guild_ids=[989384073455738930], description="Login to Valorant with Multi Factor Authentication")
async def login(ctx, 
    username:Option(str, "Username"),
    password:Option(str, "Password"),
    region:Option(str, "Region",
    choices = ['NA', 'AP', 'EU', 'KR'])):
    """Takes credentials in slash command and logs in, collects 2FA code in a Modal"""

    try:
        session = aiohttp.ClientSession()
        pattern = re.compile('access_token=((?:[a-zA-Z]|\d|\.|-|_)*).*id_token=((?:[a-zA-Z]|\d|\.|-|_)*).*expires_in=(\d*)')
        access_token, newCookie = await validatePass(username, password, session, pattern)
        if access_token == "multifactor":

            modal = MyModal(title="Enter 2FA code")
            modal.username = username
            modal.password = password
            modal.session = session
            modal.pattern = pattern
            await ctx.interaction.response.send_modal(modal)
            

        if newCookie != None:
            headers = await getJWT(access_token, session)
            userProfile = dynamodb.Table('valstore_accounts').query(KeyConditionExpression=Key('rito_username').eq(username))
            userID = await refreshProfile(username, password, region.lower(), headers, session, newCookie, userProfile)
            x = await refreshStore(username, userID, region, headers, session)
            await ctx.respond('Login successful!  You can now view your store on https://valostore.esportsforum.co.in/.')
        elif access_token == "auth_failure":
            await ctx.respond('Login failed. Please check your credentials.')
    except asyncio.TimeoutError:
        await ctx.respond('Login timed out. Please try again later.')
    except Exception as e:
        print(e)
        await ctx.respond(e)


bot.run(discordToken)