# Modules to work with ACI

import json
import requests
from requests.packages import urllib3

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
        print('\nTenants List\n------------')
        for item in data['imdata']:
            print(item['fvTenant']['attributes']['name'])
            tenants.append(item['fvTenant']['attributes']['name'])
        return tenants
    else:
        print('[!] Request Failed')
        return None


def get_tenant(host, token2, tena):
    api_url_base = 'https://{}/api/class/fvTenant.json?query-target-filter=eq(fvTenant.name,"{}")&rsp-subtree=' \
                   'full&rsp-prop-include=config-only'.format(host, tena)
    token2 = 'APIC-cookie=' + token2
    headers = {'Content-Type': 'application/json', 'Cookie': token2}
    aci_json_query_data = ''
    print('\nGetting Tenant {} detail - Only Configuration - Subtree - JSON ...'.format(tena))
    data = get_post_uri(api_url_base, headers, aci_json_query_data, is_get=True)
    show = False

    if data is not None:
        if show:
            print('\nDetail Tenant {}\n----'.format(tena))
            print(json.dumps(data, indent=4))
        return data
    else:
        print('[!] Request Failed')
        return None


def extract_data(data_dict):
    number_of_contracts = 0
    number_of_filters = 0
    number_of_app_profile = 0
    number_of_epg = 0
    full_contract_rules = {}
    full_filter_rules = {}
    full_aep_list = []
    tenant_children = data_dict['imdata'][0]['fvTenant']['children']
    # print(json.dumps(tenant_children, indent=4))

    for t_child in tenant_children:

        if 'vzBrCP' in t_child.keys():  # is a Contract
            number_of_contracts += 1
            contract_name = t_child['vzBrCP']['attributes']['name']
            contract_children_subj = t_child['vzBrCP']['children']
            subj_list = []

            for c_child_subj in contract_children_subj:
                if 'vzSubj' in c_child_subj:  # is Subject
                    subj_name = (c_child_subj['vzSubj']['attributes']['name'])
                    subj_reverse_ports = (c_child_subj['vzSubj']['attributes']['revFltPorts'])
                    subject_children_filter = c_child_subj['vzSubj']['children']
                    subj_filter_list = []
                    for s_child_filter in subject_children_filter:
                        if 'vzRsSubjFiltAtt' in s_child_filter:  # is Subj_filter
                            subj_filter_list.append((s_child_filter['vzRsSubjFiltAtt']['attributes']['action'],
                                                     s_child_filter['vzRsSubjFiltAtt']['attributes']['tnVzFilterName']))

                        if 'vzInTerm' in s_child_filter:
                            if 'children' in s_child_filter['vzInTerm']:
                                for item in s_child_filter['vzInTerm']['children']:
                                    if 'vzRsFiltAtt' in item:
                                        subj_filter_list.append((item['vzRsFiltAtt']['attributes']['action'],
                                                                 item['vzRsFiltAtt']['attributes']['tnVzFilterName']))

                        if 'vzOutTerm' in s_child_filter:
                            if 'children' in s_child_filter['vzOutTerm']:
                                for item in s_child_filter['vzOutTerm']['children']:
                                    if 'vzRsFiltAtt' in item:
                                        subj_filter_list.append((item['vzRsFiltAtt']['attributes']['action'],
                                                                 item['vzRsFiltAtt']['attributes']['tnVzFilterName']))

                    subj_list.append((subj_name, subj_reverse_ports, subj_filter_list))

            # print(contract_name, str(subj_list))

            for item in subj_list:
                for rules in item[2]:
                    if contract_name in full_contract_rules.keys():
                        full_contract_rules[contract_name].append([item[0], item[1], rules[0], rules[1]])
                    else:
                        full_contract_rules[contract_name] = [[item[0], item[1], rules[0], rules[1]]]

        elif 'vzFilter' in t_child.keys():  # is a Filter
            number_of_filters += 1
            filter_name = t_child['vzFilter']['attributes']['name']
            filter_children = t_child['vzFilter']['children']
            fe_list = []
            for f_child in filter_children:
                fe_name = f_child['vzEntry']['attributes']['name']
                fe_protocol = f_child['vzEntry']['attributes']['prot']
                fe_destination_from_port = f_child['vzEntry']['attributes']['dFromPort']
                fe_destination_to_port = f_child['vzEntry']['attributes']['dToPort']
                fe_stateful = f_child['vzEntry']['attributes']['stateful']
                fe_list.append([fe_name, fe_protocol, fe_destination_from_port, fe_destination_to_port, fe_stateful])

            full_filter_rules[filter_name] = fe_list

        elif 'fvAp' in t_child.keys():  # is a Application Profile
            number_of_app_profile += 1
            app_profile_name = t_child['fvAp']['attributes']['name']
            app_profile_children = t_child['fvAp']['children']
            epg_list = []
            for app_child in app_profile_children:
                if 'fvAEPg' in app_child.keys():  # is EPG
                    number_of_epg += 1
                    epg_name = app_child['fvAEPg']['attributes']['name']
                    epg_children = app_child['fvAEPg']['children']
                    consumed_contract_list = []
                    provided_contract_list = []
                    for epg_child in epg_children:
                        if 'fvRsCons' in epg_child.keys():  # consume contract
                            consumed_contract_list.append(epg_child['fvRsCons']['attributes']['tnVzBrCPName'])
                        elif 'fvRsProv' in epg_child.keys():  # provide contract
                            provided_contract_list.append(epg_child['fvRsProv']['attributes']['tnVzBrCPName'])

                    epg_list.append([epg_name, provided_contract_list, consumed_contract_list])
            full_aep_list.append([app_profile_name, epg_list])

    return full_aep_list, number_of_app_profile, number_of_epg, \
           full_contract_rules, number_of_contracts, \
           full_filter_rules, number_of_filters


def get_filter(f_f, f_n):
    if f_n in f_f.keys():
        return f_f[f_n]
    else:
        return [['na', 'na', 'na', 'na', 'na']]


def get_provider_epg(full_aep, consumed_contract_name):
    contract_provider_list = []

    for aep1 in full_aep:
        for epg1 in aep1[1]:
            if consumed_contract_name in epg1[1] and '-BD' not in epg1[0] and 'VLAN' not in epg1[0]:
                contract_provider_list.append(aep1[0] + "-" + epg1[0])

    return contract_provider_list


def skip_aci_epg_name(aci_epg_name, _acronysm_to_skip_in_epg_name):
    for acronysm in _acronysm_to_skip_in_epg_name:
        if acronysm in aci_epg_name:
            return True


def get_consumer_epg(full_aep, provided_contract_name, _acronysm_to_skip_in_epg_name):
    contract_consumer_list = []

    for aep1 in full_aep:
        for epg1 in aep1[1]:
            if provided_contract_name in epg1[2] and not skip_aci_epg_name(epg1[0], _acronysm_to_skip_in_epg_name):
                contract_consumer_list.append(aep1[0] + "-" + epg1[0])

    return contract_consumer_list
