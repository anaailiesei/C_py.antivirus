#!/usr/bin/python3
import re


def url_euristic_1(url_local, domains_local):
    """Rezolva primul euristic"""
    check = 0
    for line in domains_local:
        domain = line.strip()
        if domain in url_local:
            check = 1
            break
    domains_local.seek(0)
    return check


def url_euristic_2(url_local):
    """Rezolva al doilea euristic"""
    bad = ".exe"
    if bad in url_local:
        check = 1
    else:
        check = 0
    return check


def nr_digits(url_local):
    """Gaseste numarul de cifre dintr-un url/domeniu"""
    contor = 0
    for char in url_local:
        if char.isdigit():
            contor += 1
    return contor


def url_euristic_3(url_local):
    """Rezolva al treilea euristic"""
    domain = url_local.split('/')[0]
    if nr_digits(domain) > (0.1 * len(domain)):
        check = 1
    else:
        check = 0
    return check


def url_euristic_4(url_local):
    """Rezolva al patrulea euristic (gasit de mine)"""
    domain = url_local.split('/')[0]
    bad = "www"
    if bad in domain:
        check = 1
    else:
        check = 0
    return check

# ***************Functii pentru trafic malitios *******************


def get_index_of_parameter(parametru, antet_local):
    """Gaseste indexul unui parametru in antetul din traffic_in"""
    string = antet_local.split(",")
    for index, categorie in enumerate(string, 1):
        if parametru in categorie:
            return index
    return None


def traffic_euristic_1(traffic_local, antet_local):
    """Rezolva primul euristic"""
    parametru = "flow_duration"
    contor = get_index_of_parameter(parametru, antet_local)

    flow_duration = traffic_local.split(',')[contor-1]
    flow_duration = re.split(r'[ :]', flow_duration)

    days = int(flow_duration[0])
    ore = int(flow_duration[2])
    minute = int(flow_duration[3])
    sec = float(flow_duration[4])

    if days > 0 or ore > 0 or minute > 0 or sec > 1:
        check = 1
    else:
        check = 0
    return check


def traffic_euristic_2(traffic_local, antet_local):
    """Rezolva al doilea euristic"""
    parametru = "flow_pkts_payload.avg"
    contor = get_index_of_parameter(parametru, antet_local)
    flow_pkts_payload = traffic_local.split(',')[contor-1]
    if float(flow_pkts_payload) != 0:
        return 1
    return 0

# ***************Incepe "main-ul"*******************


# ***************Url malitios*******************
with open('./data/urls/urls.in', 'r', encoding='utf-8') as url_in, \
        open('urls-predictions.out', 'w', encoding='utf-8') as url_out, \
        open('./data/urls/domains_database', 'r', encoding='utf-8') as domains_in:

    for url in url_in:
        URL_E1 = url_euristic_1(url, domains_in)
        URL_E2 = url_euristic_2(url)
        URL_E3 = url_euristic_3(url)
        URL_E4 = url_euristic_4(url)

        if URL_E1 == 1 or URL_E2 == 1 or URL_E3 == 1 or URL_E4 == 1:
            url_out.write("1\n")
        else:
            url_out.write("0\n")

# ***************Trafic malitios*******************

with open('./data/traffic/traffic.in', 'r', encoding='utf-8') as traffic_in, \
        open('traffic-predictions.out', 'w', encoding='utf-8') as traffic_out:

    antet = traffic_in.readline()
    for traffic in traffic_in:
        TRAFFIC_E1 = traffic_euristic_1(traffic, antet)
        TRAFFIC_E2 = traffic_euristic_2(traffic, antet)
        if TRAFFIC_E1 == 1 and TRAFFIC_E2 == 1:
            traffic_out.write("1\n")
        else:
            traffic_out.write("0\n")
