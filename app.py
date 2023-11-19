import re
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn import tree
from colorama import Fore
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.naive_bayes import GaussianNB
from tld import get_tld, is_tld
import streamlit as st
from PIL import Image
import pickle

#--------------------------------------------------------------------------------------------#
# DECORATION
st.set_page_config(
    page_title="Home",
    page_icon="👋",
)

st.sidebar.subheader('What is Phishing URL ?')
st.sidebar.info(
    """
    A phishing URL is a website address deliberately 
    crafted by cybercriminals to imitate the look of a genuine site, 
    aiming to deceive users into divulging sensitive details 
    like usernames, passwords, credit card numbers, 
    or other personal information.
    """,
    icon="👾")

st.sidebar.subheader('What is the Impact of Phishing ?')
st.sidebar.info(
    """
    The impact of phishing can be highly detrimental, both for individuals and organizations. 
    Some common consequences of phishing attacks involve information security, 
    financial loss, and reputational damage, including loss of personal data
    spread of malware, financial loss, and organizational reputation.
    """,
    icon="📛")

def new_line(n=1):
    for i in range(n):
        st.write("\n")
# Logo 
col1, col2, col3 = st.columns([0.25,1,0.25])
col2.image("pngegg.png", use_column_width=True)
new_line(2)

# Description
st.markdown("""Welcome to Phising URL Detection, the easy-to-use platform for predicting malicious and unsafe URL
            with just a click. It involves employing predictive technologies, 
    driven by machine learning algorithms, to anticipate and identify potential phishing URLs prior to users accessing them. 
    This proactive strategy seeks to improve cybersecurity by forecasting 
    and preventing the use of malicious URLs in phishing attacks.""", unsafe_allow_html=True)
st.divider()

st.markdown("<h2 align='center'> <b> Input Your URL", unsafe_allow_html=True)
new_line(1)

urls = st.text_input("", "")

#--------------------------------------------------------------------------------------------#
# APP
# Add custom CSS to hide the GitHub icon

def check_valid_url(url):
    if not url.startswith("http"):
        url = "http://" + url

    try:
        ip_pattern = re.compile(r'''
            ((([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5]))|
            ((([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5]):\d+)|
            ((0x[0-9a-fA-F]{1,2}\.){3}(0x[0-9a-fA-F]{1,2}))|
            (([a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4})|
            ([0-9]+(?:\.[0-9]+){3}:[0-9]+)|
            ((\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d|\d)(/\d{1,2})?
        ''', re.X)

        has_ip = ip_pattern.search(url)

        if has_ip:
            return True

        domain = get_tld(url, as_object=True)
        return domain.fld is not None

    except Exception as e:
        print(f"Error: {e}")
        return False


def process_tld(url):
    try:
        res = get_tld(url, as_object = True, fail_silently=False,fix_protocol=True)
        pri_domain= res.parsed_url.netloc
    except :
        pri_domain= None
    return pri_domain

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        return 1
    else:
        return 0
    
def httpSecure(url):
    htp = urlparse(url).scheme
    match = str(htp)
    if match=='https':
        return 1
    else:
        return 0
    
def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

def Shortining_Service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.g|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4 with port
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
        '((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', url)  # Ipv6
    if match:
        return 1
    else:
        return 0

def URL_Converter(urls):
    data= pd.DataFrame()
    data['url'] = pd.Series(urls)
    data['url_len'] = data['url'].apply(lambda x: len(str(x)))
    data['domain'] = data['url'].apply(lambda i: process_tld(i))
    feature = ['@','?','-','=','.','#','%','+','$','!','*',',','//']
    for a in feature:
        data[a] = data['url'].apply(lambda i: i.count(a))
    data['abnormal_url'] = data['url'].apply(lambda i: abnormal_url(i))
    data['https'] = data['url'].apply(lambda i: httpSecure(i))
    data['digits']= data['url'].apply(lambda i: digit_count(i))
    data['letters']= data['url'].apply(lambda i: letter_count(i))
    data['Shortining_Service'] = data['url'].apply(lambda x: Shortining_Service(x))
    data['having_ip_address'] = data['url'].apply(lambda i: having_ip_address(i))
    print(data.columns)
    X = data.drop(['url','domain'],axis=1)
    return X

is_valid_url = check_valid_url(urls)

if urls:
    if is_valid_url == False:
        st.error("Warning: This isn't a valid URL. Please check your URL.")
    else:
        test_data = URL_Converter(urls)
    
        load_model = pickle.load(open('phising.pkl', 'rb')) # the model has been saved with the name "phising.pkl" and builded using Random Forest Classifier algorithm
        
        prediction = load_model.predict(test_data)
        
        if prediction == 1:
            st.success("This isn't a Phishing URL :thumbsup:")
        else:
            st.error("Phishing URL :thumbsdown:")
else:
    pass
