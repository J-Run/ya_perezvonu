from telegram.ext import Updater, CommandHandler, Filters, MessageHandler, InlineQueryHandler
from telegram  import InlineQueryResultArticle, InputTextMessageContent
from getcontact import get_number_info, send_captcha_bot
import argparse
import logging
import sqlite3
import sys
import re
import os

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                     level=logging.INFO)

help_desc = '''
This is telegram bot that allows you to easily get info about phone numbers using reversed API of `GetContact` android app
--- chipik
'''

parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-t', '--token', help='Telegram bot token (Ex.: 745763762:AAEmrlc5SjARqUEXcc0RS10SmkdSu9gY724)')
parser.add_argument('-v', '--debug', action='store_true', help='Show debug info')
args = parser.parse_args()

bot_token = args.token
sqlite_file = 'bot_db.sqlite'


def init_logger(logname, level):
    # generic log conf
    logger = logging.getLogger(logname)
    logger.setLevel(level)
    console_format = logging.Formatter("[%(levelname)-5s] %(message)s")
    # console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(console_format)
    logger.addHandler(ch)
    return logger

if args.debug:
    logger = init_logger("ya_perezvonu", logging.DEBUG)
else:
    logger = init_logger("ya_perezvonu", logging.INFO)



def create_connection(db_file):
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except sqlite3.Error as e:
        logger.info(e)
    return None

def start(bot, update):
    bot.send_message(chat_id=update.message.chat_id, text="This Bot allows you to get information about phone number.\n"
                                                          "Feel free to use it while it works :)\n"
                                                          "Contacts: telegram: @Chpkk\n"
                                                          "I am not guilty if you quarrel with your partner after this (lol)")

def help(bot, update):
    help_msg = "Just type the phone number and you will get an answer.\n" \
               "You can control me by sending these commands:\n" \
               "/help - this message\n"\
               "/remain -  number of requests remaining (300 requests a day)\n" \
               "/captcha - enter captcha\n" \
               "/batya - about\n" \
               "Have fun!"
    bot.send_message(chat_id=update.message.chat_id, text=help_msg)

def get_phone_info(bot, chat_id,  user, phone_number):
    format_text = "Please use this phone format: +XXXXXXXXXXX (Ex: +79876543210)"
    to_client = ""
    if '+' not in phone_number:
        phone_number = "+{}".format(phone_number)
    if not re.match("\+\d*", phone_number): #best regex eeeeeevvveeeer! :P)
        to_client =  "Wrong phone number!\n{}".format(format_text)
    rez = get_number_info(phone_number)
    if rez[0] == 200:
        to_client = preapare_msg(rez[1][0]["displayName"], rez[1][0]["tags"], 0)
        log_reamins(rez[1][1])
    if rez[0] == 400:
        to_client = "Wrong phone number!\n{}".format(format_text)
    if rez[0] == 404:
        to_client = "Nothing found :("
    if rez[0] == 403:
        if rez[1][0] == '403004':
            to_client = "Captcha happend! Type */captcha code_from_picture*"
            capthca_img = rez[1][1]
            bot.send_photo(chat_id=chat_id, photo=open(capthca_img, 'rb'))
        elif rez[1][0] == '403020':
            to_client = "We will begin to show results soon for this country"
        else:
            to_client = "Something wrong"
    log_request("{}".format(user.name), phone_number, to_client)
    logger.info("Result:{}".format(to_client.encode('utf-8').strip()))
    return to_client

def get_info(bot, update, user_data):
    if get_reamins() > 10:
        logger.info("{} is searching for {}".format(update.message.from_user.name, update.message.text))
        bot.send_message(chat_id=update.message.chat_id, text=get_phone_info(bot, update.message.chat_id,  update.message.from_user, update.message.text), parse_mode="Markdown")
    else:
        bot.send_message(chat_id=update.message.chat_id, text="Sorry, but we have reached limit for today :(",
                         parse_mode="Markdown")


def get_remain(bot, update):
    bot.send_message(chat_id=update.message.chat_id, text="Remain {} requests".format(get_reamins()), parse_mode="Markdown")

def get_about(bot, update):
    bot.send_message(chat_id=update.message.chat_id, text="Hi {}.\n@Chpkk moy batya!".format(update.message.from_user.username), parse_mode="Markdown")

def inline_get_info(bot, update):
    query = update.inline_query.query
    if not query:
        return
    results = list()
    results.append(
        InlineQueryResultArticle(
            id=query.upper(),
            title='Check phone',
            input_message_content=InputTextMessageContent(get_phone_info(query), parse_mode="Markdown")
        )
    )
    bot.answer_inline_query(update.inline_query.id, results)

def get_captcha(bot, update, args):
    if len(args):
        logger.info("Got captcha from user: {}".format(args[0]))
        if send_captcha_bot(args[0]):
            logger.info("Wrong captcha from user")
            bot.send_message(chat_id=update.message.chat_id, text="Wrong captcha")
        else:
            logger.info("Captcha passed")
            bot.send_message(chat_id=update.message.chat_id, text="Captcha passed. Try to send phone number")
    else:
        logger.info("Empty captcha")
        bot.send_message(chat_id=update.message.chat_id, text="Send captcha from picture. Ex.: /captcha OLoLoH")


def unknown(bot, update):
    bot.send_message(chat_id=update.message.chat_id, text="Sorry, I didn't understand that command.\nUse /help")

def preapare_msg(name,tags, remain):
    if remain:
        rez = "{}\n{}\nRemain:{}".format(name,'\n'.join(tags), remain)
    else:
        rez = "*We have found:*\n"+name+"\n"+'\n'.join(tags)
    return rez


def log_request(user, requested_phone, response):
    conn = create_connection(sqlite_file)
    try:
        c = conn.cursor()
        insert_log = "INSERT INTO logs (user_name, requested_phone, response) VALUES (?, ?, ?)"
        c.execute(insert_log, (user, requested_phone, response,))
        conn.commit()
        conn.close()
    except:
        conn.rollback()
        conn.close()
        raise RuntimeError("Uh oh, an error occurred ...{}")

def log_reamins(remain):
    conn = create_connection(sqlite_file)
    try:
        c = conn.cursor()
        update_rem = "UPDATE remain SET count=?"
        c.execute(update_rem, (remain,))
        conn.commit()
        conn.close()
    except:
        conn.rollback()
        conn.close()
        raise RuntimeError("Uh oh, an error occurred ...{}")


def get_reamins():
    conn = create_connection(sqlite_file)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    select_rem = "SELECT count from remain"
    result = c.execute(select_rem).fetchone()['count']
    conn.close()
    return result

def create_db():
    logger.info("Creating new DB")
    conn = create_connection(sqlite_file)
    c = conn.cursor()
    c.execute("CREATE TABLE {} ({} {})".format("remain", "count", "INTEGER"))
    c.execute("INSERT INTO remain (count) VALUES (300)")
    c.execute("CREATE TABLE {} ("
              "{} {} PRIMARY KEY,"
              "{} {} NOT NULL,"
              "{} {} NOT NULL,"
              "{} {}"
              ")".format("logs",
                         "id", "INTEGER",
                         "user_name", "TEXT",
                         "requested_phone", "TEXT",
                         "response", "TEXT"))
    conn.commit()
    conn.close()

if not os.path.isfile(sqlite_file):
    create_db()

updater = Updater(bot_token)
dispatcher = updater.dispatcher

start_handler = CommandHandler('start', start)
help_handler = CommandHandler('help', help)
remain_handler = CommandHandler('remain', get_remain)
about_handler = CommandHandler('batya', get_about)
phone_handler = MessageHandler(Filters.text, get_info, pass_user_data=True)
inline_phone_handler = InlineQueryHandler(inline_get_info)
captcha_handler = CommandHandler('captcha', get_captcha, pass_args=True)
unknown_handler = MessageHandler(Filters.command, unknown)

dispatcher.add_handler(start_handler)
dispatcher.add_handler(help_handler)
dispatcher.add_handler(remain_handler)
dispatcher.add_handler(phone_handler)
dispatcher.add_handler(inline_phone_handler)
dispatcher.add_handler(about_handler)
dispatcher.add_handler(captcha_handler)
dispatcher.add_handler(unknown_handler)


logger.info("Starting...")
updater.start_polling()
updater.idle()