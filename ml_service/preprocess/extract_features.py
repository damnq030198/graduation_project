import dns.resolver
from new_extract import *



def extract_feature(domain,label,listfeature):
    listfeature['domain'].append(domain)
    listfeature['label'].append(label)
    myResolver = dns.resolver.Resolver()
    myResolver.nameservers = ['8.8.8.8', '8.8.4.4']
    DNlenght= domain_length(domain)
    listfeature['domain_name_length'].append(DNlenght)
    DNtokencount=domain_name_token_count(domain)
    listfeature['domain_name_token_count'].append(DNtokencount)
    Avgtokenlenght=avg_domain_token_len(domain)
    listfeature['avg_domain_token_len'].append(Avgtokenlenght)
    longtoken=longest_token(domain)
    listfeature['longest_token'].append(longtoken)
    numberipindomain=number_of_IP(domain)
    listfeature['IP_in_domain'].append(numberipindomain)
    numberspecialchar=number_special_char(domain)
    listfeature['number_special_char'].append(numberspecialchar)
    numberdigits=number_digits(domain)
    listfeature['number_digits'].append(numberdigits)
    numbercondigit=number_con_digits(domain)
    listfeature['number_con_digits'].append(numbercondigit)
    longdigit=longest_digits(domain)
    listfeature['longest_digits'].append(longdigit)
    numberletter=number_letters(domain)
    listfeature['number_letters'].append(numberletter)
    numconletter=number_con_letters(domain)
    listfeature['number_con_letters'].append(numconletter)
    lgt_letter=longest_letters(domain)
    listfeature['longest_letters'].append(numconletter)
    brand_name=EmbeddedBrandName(domain)
    listfeature['EmbeddedBrandName'].append(brand_name)
    host_rank,country_rank=ranking_alexa(domain)
    listfeature['host_rank'].append(host_rank)
    listfeature['country_rank'].append(country_rank)
    domcop_rank=ranking_domcop(domain)
    listfeature['domcop_rank'].append(domcop_rank)
    agedomain=age_of_domain(domain)
    listfeature['age_of_domain'].append(agedomain)
    nxdomain,countIP,listip=Resolved_IP_count(myResolver,domain)
    #listfeature['NXDOMAIN'].append(nxdomain)
    listfeature['Resolved_IP_count'].append(countIP)
    mail_exchange=Mail_exchange_server_count(myResolver,domain)
    listfeature['Mail_exchange_server_count'].append(mail_exchange)
    nscount=Name_server_count(myResolver,domain)
    listfeature['Name_server_count'].append(nscount)
    #distinctcountry=Distinct_country_count(listip)
    #listfeature['Distinct_country_count'].append(distinctcountry)
    http_response=HTTP_response_status(domain)
    listfeature['HTTP_response_status'].append(http_response)
    ttl=Time_to_live(myResolver,domain)
    listfeature['Time_to_live'].append(ttl)
    ssl=SSL_certification(domain)
    
    listfeature['SSL_certification'].append(ssl)
    # countdomain=ip2domain(listip)
    # print(countdomain)
    #listfeature['ip2domain'].append(countdomain)
    #srvcount=SRVcount(myResolver,domain)

    #listfeature['SRVcount'].append(srvcount)
    #cname= cnamecount(myResolver,domain)
    #listfeature['cnamecount'].append(cname)

    #return dict(listfeature)




#print(dict(extract_feature("facebook.com",0)))


    