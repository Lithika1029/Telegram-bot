import os
import telebot
import pandas as pd
import joblib
import psutil
import validators
import whois
from datetime import datetime


BOT_TOKEN = os.environ.get('BOT_TOKEN')
bot = telebot.TeleBot(BOT_TOKEN)

# Load the trained phishing detection model
model = joblib.load('phishing_model.pkl')

#import validators  # Install via pip install validators
from urllib.parse import urlparse

def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.now() - creation_date).days // 365
        return age
    except:
        return 0  # If WHOIS fails, return 0
    

# Refined feature extraction from the message (URL)
def extract_features_from_message(url):
    # Validate URL
    if not validators.url(url):
        raise ValueError("Invalid URL")

    parsed_url = urlparse(url)
    print(parsed_url)
    domain = parsed_url.netloc
    domain_age = get_domain_age(domain)

    features = {
        'Index': 0,
        'UsingIP': int(domain and domain[0].isdigit()),
        'LongURL': int(len(url) > 75),
        'ShortURL': int(len(url) < 20),
        'Symbol@': int('@' in url),
        'Redirecting//': int(url.count('//') > 1),
        'PrefixSuffix-': int('-' in domain),
        'SubDomains': domain.count('.') - 1,
        'HTTPS': int(parsed_url.scheme == 'https'),
        'DomainRegLen': domain_age if domain_age > 0 else 12,  # Use WHOIS; default to 12 if unavailable
        'Favicon': 0,  # Default placeholder
        'NonStdPort': int(parsed_url.port not in (80, 443) if parsed_url.port else 0),
        'HTTPSDomainURL': int('https' in domain),
        'RequestURL': 0,  # Placeholder
        'AnchorURL': 0,  # Placeholder
        'LinksInScriptTags': 0,  # Placeholder
        'ServerFormHandler': 0,  # Placeholder
        'InfoEmail': int('info@' in url),
        'AbnormalURL': 0,  # Placeholder
        'WebsiteForwarding': 0,  # Placeholder
        'StatusBarCust': 0,  # Placeholder
        'DisableRightClick': 0,  # Placeholder
        'UsingPopupWindow': 0,  # Placeholder
        'IframeRedirection': 0,  # Placeholder
        'AgeofDomain': domain_age if domain_age > 0 else 12,  # WHOIS result or fallback
        'DNSRecording': 0,  # Placeholder
        'WebsiteTraffic': 0,  # Placeholder
        'PageRank': 0,  # Placeholder
        'GoogleIndex': 0,  # Placeholder
        'LinksPointingToPage': 0,  # Placeholder
        'StatsReport': 0  # Placeholder

    }
    return features

# Define feature order to match the model
feature_order = [
    'Index', 'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 
    'PrefixSuffix-', 'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon',
    'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL', 
    'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail', 'AbnormalURL', 
    'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick', 
    'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 
    'DNSRecording', 'WebsiteTraffic', 'PageRank', 'GoogleIndex', 
    'LinksPointingToPage', 'StatsReport'
]

# url_features = extract_features_from_message('https://www.yourcompany-update.fakewebsite.com/login')
# feature_df = pd.DataFrame([url_features])[feature_order]
# prediction = model.predict(feature_df)
# print(prediction)



@bot.message_handler(func=lambda message: message.text.startswith("http"))
def detect_phishing_url(message):
    try:
        # Extract features from the URL message
        url_features = extract_features_from_message(message.text)
        feature_df = pd.DataFrame([url_features])[feature_order]

        # Make prediction using the model
        prediction = model.predict(feature_df)

        # Respond based on the prediction
        if prediction[0] == 0:
            response = f"🚨 Warning: The URL appears to be a phishing link!\n{message.text}"
        else:
            response = f"✅ The URL seems safe.\n{message.text}"
    except ValueError as ve:
        response = f"Error: {str(ve)}"
    except Exception as e:
        response = f"Error: Unable to process the URL. Details: {str(e)}"
    
    bot.reply_to(message, response)


# Welcome command
@bot.message_handler(commands=['start', 'hello'])
def send_welcome(message):
    bot.reply_to(message, "Hi, how are you doing?")

# System Info command
@bot.message_handler(func=lambda message: message.text.lower() == "system info")
def send_system_info(message):
    # Get memory and CPU usage
    memory = psutil.virtual_memory()
    total_memory = memory.total // (1024 * 1024)  # Convert to MB
    used_memory = memory.used // (1024 * 1024)   # Convert to MB
    cpu_usage = psutil.cpu_percent(interval=1)   # CPU usage in percentage

    # Prepare and send the response
    response = (
        f"System Info:\n"
        f"Total RAM: {total_memory} MB\n"
        f"Used RAM: {used_memory} MB\n"
        f"CPU Usage: {cpu_usage}%"
    )
    bot.reply_to(message, response)

# Start the bot
bot.infinity_polling()
