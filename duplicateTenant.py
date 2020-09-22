#!/usr/bin/env python3

# Script to list Tenants and duplicate one with a new name

import requests
import json
import sys
from requests.packages import urllib3
from time import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

tenants = []


def get_post_uri(api_url_base, headers, aci_json_query_data, is_get):

    if is_get:
        response = requests.get(api_url_base, headers=headers, data=aci_json_query_data, verify=False)
    else:
        response = requests.post(api_url_base, headers=headers, data=aci_json_query_data, verify=False)

    if response.status_code >= 500:
        print('[!] [{0}] Server Error'.format(response.status_code))
        return None
    elif response.status_code == 404:
        print('[!] [{0}] URL not found: [{1}]'.format(response.status_code, api_url_base))
        return None
    elif response.status_code == 401:
        print('[!] [{0}] Authentication Failed'.format(response.status_code))
        return None
    elif response.status_code == 400:
        print('[!] [{0}] Bad Request'.format(response.status_code))
        return None
    elif response.status_code >= 300:
        print('[!] [{0}] Unexpected Redirect'.format(response.status_code))
        return None
    elif response.status_code == 200:
        return json.loads(response.content.decode('utf-8'))
    else:
        print('[?] Unexpected Error: [HTTP {0}]: Content: {1}'.format(response.status_code, response.content))
    return None


def login(host, user, passwd):
    api_url_base = 'https://{}/api/aaaLogin.json'.format(host)
    headers = {'Content-Type': 'application/json'}
    dict_query_data = {"aaaUser": {"attributes": {"name": "", "pwd": ""}}}
    dict_query_data['aaaUser']['attributes']['name'] = user
    dict_query_data['aaaUser']['attributes']['pwd'] = passwd
    aci_json_query_data = json.dumps(dict_query_data)
    data = get_post_uri(api_url_base, headers, aci_json_query_data, is_get=False)

    if data is not None:
        return data['imdata'][0]['aaaLogin']['attributes']['token']
    else:
        print('[!] Request Failed')
        return None


def get_tenants(host, token2):
    api_url_base = 'https://{}/api/node/class/fvTenant.json'.format(host)
    token2 = 'APIC-cookie=' + token2
    headers = {'Content-Type': 'application/json', 'Cookie': token2}
    aci_json_query_data = ''
    data = get_post_uri(api_url_base, headers, aci_json_query_data, is_get=True)

    if data is not None:
        # print(json.dumps(data, indent=4))
        print('Tenants List\n============')
        for item in data['imdata']:
            print(item['fvTenant']['attributes']['name'])
            tenants.append(item['fvTenant']['attributes']['name'])
    else:
        print('[!] Request Failed')
        return None


def get_tenant(host, token2, tena):
    api_url_base = 'https://{}/api/class/fvTenant.json?query-target-filter=eq(fvTenant.name,"{}")&rsp-subtree=full&rsp-prop-include=config-only'.format(host, tena)
    token2 = 'APIC-cookie=' + token2
    headers = {'Content-Type': 'application/json', 'Cookie': token2}
    aci_json_query_data = ''
    print('\nGetting Tenant {} detail - Only Configuration - Subtree - JSON ...'.format(tena))
    data = get_post_uri(api_url_base, headers, aci_json_query_data, is_get=True)

    if data is not None:
        print('\nDetail Tenant {}\n===='.format(tena))
        print(json.dumps(data, indent=4))
        # print(data)
        return data
    else:
        print('[!] Request Failed')
        return None


def create_tenant(host, token2, tena, new_tena, config):
    api_url_base = 'https://{}/api/node/mo/uni/tn-{}.json'.format(host, new_tena)
    token2 = 'APIC-cookie=' + token2
    headers = {'Content-Type': 'application/json', 'Cookie': token2}
    aci_json_query_data = json.dumps(config)
    aci_json_query_data = aci_json_query_data.replace(tena, new_tena)

    data = get_post_uri(api_url_base, headers, aci_json_query_data, is_get=False)

    if data is not None:
        print('\nTenant {} Created \n===='.format(new_tena))
        print(json.dumps(data, indent=4))
    else:
        print('[!] Request Failed')
        return None


if __name__ == '__main__':
    apic_host = input('APIC hostname (default: sandboxapicdc.cisco.com): ')
    if apic_host == '':
        apic_host = 'sandboxapicdc.cisco.com'
    username = input('username (default: admin): ')
    if username == '':
        username = 'admin'
    password = input('password (default: ciscopsdt): ')
    if password == '':
        password = 'ciscopsdt'
    print('Logging in...')
    token = login(apic_host, username, password)
    if token is not None:
        print('Logging Successful\nGetting tenants list...')
        get_tenants(apic_host, token)
    else:
        print('Logging Failed')
        sys.exit(1)
    start_login_expired_timer = time()
    ten = input('\nSelect tenant name: ')
    if ten not in tenants:
        print('\nInput Error. Select a tenant from the list.\n')
        sys.exit(1)

    new_tenant_name = input('\nNew tenant name: ')
    if new_tenant_name == '':
        print('\nInput Error. Type the new tenant name.\n')
        sys.exit(1)

    end_login_expired_timer = time()

    if end_login_expired_timer - start_login_expired_timer >= 55:
        print('Expired token, re logging ...')
        token = login(apic_host, username, password)
        if token is not None:
            print('Logging Successful\n')
            get_tenants(apic_host, token)
        else:
            print('Logging Failed')
            sys.exit(1)

    config = get_tenant(apic_host, token, ten)

    end_login_expired_timer = time()
    if end_login_expired_timer - start_login_expired_timer >= 55:
        print('Expired token, re logging ...')
        token = login(apic_host, username, password)
        if token is not None:
            print('Logging Successful\n')
            get_tenants(apic_host, token)
        else:
            print('Logging Failed')
            sys.exit(1)

    create_tenant(apic_host, token, ten, new_tenant_name, config)