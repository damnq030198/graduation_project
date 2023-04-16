import re 
import requests
from bs4 import BeautifulSoup
import whois
import socket
import tldextract
import time
import json
import ipaddress
import ssl
import pandas as pd
#from fuzzywuzzy import fuzz
from dns.resolver import NXDOMAIN

#1 Domain name length
def domain_length(url):
    return len(url)

#2 Domain name token count
def domain_name_token_count(url):
    return url.count('.')+1

#3 Average domain token length
def avg_domain_token_len(url):
    words = url.split('.')
    total_len = 0
    for word in words:
        total_len += len(word)
    return total_len/len(words)


#4 Longest domain token length
def longest_token(url):
    words = url.split('.')
    longest_string = max(words, key=len)
    return len(longest_string)

#5 Number of IP address in domain name
def number_of_IP(url):
    array_ip = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)
    return len(array_ip)

#6 Number of special characters
def number_special_char(url):
    count = 0
    for char in url:
        if (not char.isalpha() and not char.isdigit() and char != '.'):
           count += 1
    return count

#7 Number of digits
def number_digits(url):
    count = 0
    for char in url:
        if(char.isdigit()):
            count += 1
    return count

#8 Number of continuous digits
def number_con_digits(url):
    digits = re.findall(r'[0-9]+', url)
    return len(digits)

#9 Longest continuous digits length
def longest_digits(url): 
    try:
        digits = max(re.findall(r'[0-9]+', url), key = len) 
    except:
        return 0
    return len(digits)

#10 Number of lettters
def number_letters(url):
    count = 0
    for char in url:
        if(char.isalpha()):
            count += 1
    return count

#11 Number of continuous letters
def number_con_letters(url):
    letters = re.findall(r'[a-zA-Z]+', url)
    #print(letters)
    return len(letters)

#12 Longest continuous letters length
def longest_letters(url):
    try:
        letters = max(re.findall(r'[a-zA-Z]+', url), key = len)
        #print(letters)
    except:
        return 0
    return len(letters)


#13 Maximum Levenshtein ratio
# def Levenshtein_ratio(domainuser,domainip):
#     return fuzz.ratio(domainuser,domainip)

#14 Brand name presence (check)
def EmbeddedBrandName(domain):
        url="https://autocomplete.clearbit.com/v1/companies/suggest?query="+domain
        response=""
        the_page =""
        for i in range(2):
            try:
                
                response = requests.get(url)
            except:
                time.sleep(1)
        if response =="":
            return 0
        else:
            the_page = response.content.decode("utf-8")

        #r=requests.get(url,verify=False,allow_redirects=True)
        strlist={"name","domain","logo"}
        for i in strlist :
                if i in the_page:
                    return 1
        return 0


#15,16 Rank in Alexa host and country
def ranking_alexa(url):
        xmlpath='http://data.alexa.com/data?cli=10&dat=snbamz&url='+url
        rank_country=-1
        rank_host=-1
        #print xmlpath
        try:
            r=requests.get(xmlpath)
            #print r.content
            rlist=r.content.split('>'.encode())
            for i in rlist:
                
                if 'REACH'.encode() in i and 'RANK='.encode() in i:
                    if int(i.split("\"".encode())[-2])<10000000:
                        rank_host= i.split("\"".encode())[-2].decode()
                if 'COUNTRY'.encode() in i and 'RANK='.encode() in i:
                    if int(i.split("\"".encode())[-2])<10000000:
                        rank_country=i.split("\"".encode())[-2].decode()
            return [int(rank_host),int(rank_country)]
        except:
            return [-1,-1]

#17 Rank in Domcop
def ranking_domcop(url):
    df = pd.read_csv('top10milliondomains.csv')
    domain = url+'$'
    a = df.loc[df['Domain'].str.match(domain)]
    if len(a['Rank']) == 0:
        return -1
    return int(a['Rank'].iloc[0])


#18 age of domain (check)
def age_of_domain(domain):# year
    try:
        age= whois.query(domain)
        #print age.__dict___
        creation_date = age.creation_date
        #print(creation_date)
        expiration_date = age.expiration_date
        #print(expiration_date)
    except:
        return 0
    ageofdomain = 0
    if expiration_date:
        ageofdomain = abs((expiration_date - creation_date).days)
        #print ageofdomain
    return 1 if ageofdomain/180 > 1 else 0

#19 get IP dns query
def Resolved_IP_count(myresovler,domain):
    nxdomain=0
    count = 0
    listip =[]
    try :
        answers=myresovler.query(domain,"A")
        for ip in answers:
            listip.append(ip.to_text())
            count+=1
    except NXDOMAIN:
        nxdomain=1
        return nxdomain,count,listip
    except :
        pass
    return nxdomain,count,listip
#20 count mail exchange
def Mail_exchange_server_count(myresovler,domain):
    count=0
    try :
        answers=myresovler.query(domain,'MX')
        for mx in answers:
            #print(mx)
            count+=1
    except:
        return 0
    return count
# 21 count name server 
def Name_server_count(myresovler,domain):
    count=0
    try :
        answers=myresovler.query(domain,'NS')
        for mx in answers:
            #print(mx)
            count+=1
    except:
        return 0
    return count

#22 count country in ip
def Distinct_country_count(listip):
    if len(listip)==0:
        return 0
    else:
        count=0
        for ip in listip:
            try:
                url = 'https://ipinfo.io/' + ip + '/json'
                response = urlopen(url)
                data = json.load(response)
                if data['country']:
                    count +=1
            except:
                pass
    return count
    
#23 HTTP status code
def HTTP_response_status(domain):
    if domain =='':
        return 0
    else:
        try:
            url='http://'+domain
            res= requests.get(url=url)
        except:
            return 0
    return res.status_code

# detection ip private
def dectection_ip_private(listip):
    if len(listip)==0:
        return True
    for ip in listip:
        #print(ipaddress.ip_address(ip).is_private)
        if ipaddress.ip_address(ip).is_private:
            return True
    return False

#24 time to live
def Time_to_live(myresovler,domain):
    try:
        answer = myresovler.query(domain)
    except:
        return 0
    return answer.rrset.ttl

#25 Check SSL
def SSL_certification(domain):
    try:
        cert_pem =ssl.get_server_certificate((domain,443))
    except:
        return 0
    return 1 if cert_pem else 0

#26 Count domain in ip
def ip2domain(listip):
    if len(listip)==0:
        return 0
    count=0
    for ip in listip:
        try:
            domain = socket.gethostbyaddr(ip)[0]
            count+=1
            #print(domain)
        except:
            return 0
    return count

