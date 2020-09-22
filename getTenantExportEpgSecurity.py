#!/usr/bin/env python3

# Script to connect to an Cisco ACI APIC, download a Tenant and export information
# 1.- to screen AEPg, EPG, provider/consumer, contract
# 2.- to screen Contract, Subject, Filter, Filter Name, ports, etc
# 3.- export to excel format the full combination of: AEPg, EPG, provider/consumer,
#     contract, subject, filter and filter name, ports, etc

import requests
import json
import sys
from requests.packages import urllib3
from time import time, perf_counter
import os
from datetime import date
import xlsxwriter

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
        print('\nTenants List\n============')
        for item in data['imdata']:
            print(item['fvTenant']['attributes']['name'])
            tenants.append(item['fvTenant']['attributes']['name'])
    else:
        print('[!] Request Failed')
        return None


def get_tenant(host, token2, tena):
    api_url_base = 'https://{}/api/class/fvTenant.json?query-target-filter=eq(fvTenant.name,"{}")&rsp-subtree=full&rsp-prop-include=config-only'.format(
        host, tena)
    token2 = 'APIC-cookie=' + token2
    headers = {'Content-Type': 'application/json', 'Cookie': token2}
    aci_json_query_data = ''
    print('\nGetting Tenant {} detail - Only Configuration - Subtree - JSON ...'.format(tena))
    data = get_post_uri(api_url_base, headers, aci_json_query_data, is_get=True)

    show = False

    if data is not None:
        if show:
            print('\nDetail Tenant {}\n===='.format(tena))
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
                if 'fvAEPg' in app_child.keys():    # is EPG
                    number_of_epg += 1
                    epg_name = app_child['fvAEPg']['attributes']['name']
                    epg_children = app_child['fvAEPg']['children']
                    consumed_contract_list = []
                    provided_contract_list = []
                    for epg_child in epg_children:
                        if 'fvRsCons' in epg_child.keys():      # consume contract
                            consumed_contract_list.append(epg_child['fvRsCons']['attributes']['tnVzBrCPName'])
                        elif 'fvRsProv'in epg_child.keys():     # provide contract
                            provided_contract_list.append(epg_child['fvRsProv']['attributes']['tnVzBrCPName'])

                    epg_list.append([epg_name, provided_contract_list, consumed_contract_list])
            full_aep_list.append([app_profile_name, epg_list])

    return full_aep_list, number_of_app_profile, number_of_epg,\
           full_contract_rules, number_of_contracts,\
           full_filter_rules,  number_of_filters


def nice_print_contracts(f_c, f_f):
    # print(json.dumps(f_c, indent=4))
    # print(json.dumps(f_f, indent=4))
    text = ''
    text += '{:<24} {:<25} {:<7} {:<8} {:<21} {:<22} {:<7} {:<8} {:<8} {:<8}\n'.format(
        'Contract Name', 'Subject Name', 'BiDir', 'Action',
        'Filter Name', 'Filter Entry Name', 'Proto', 'D.F.Port', 'D.T.Port',
        'StFull')
    text += '=' * 145 + '\n'

    sorted_f_c = sorted(f_c.items(), key=lambda x: x[1])

    for contract_name in sorted_f_c:
        for subject in f_c[contract_name[0]]:
            fe_list = list(get_filter(f_f, subject[3]))
            for f_e in fe_list:
                if f_e[1] == 'unspecified':
                    f_e[1] = 'any'
                if f_e[2] == 'unspecified':
                    f_e[2] = 'any'
                if f_e[3] == 'unspecified':
                    f_e[3] = 'any'
                text += '{:<24} {:<25} {:<7} {:<8} {:<21} {:<22} {:<7} {:<8} {:<8} {:<8}\n'.format(
                    contract_name[0], subject[0], subject[1], subject[2],
                    subject[3], f_e[0], f_e[1], f_e[2],
                    f_e[3], f_e[4])
    return text


def nice_print_aepg(f_a):
    # print(json.dumps(f_a, indent=4))
    text = ''
    text += '{:<25} {:<25} {:^17} {:<20} \n'.format(
        'AEPg Name', 'EPG Name', 'Provide/Consume', 'Contract Name')
    text += '=' * 93 + '\n'

    for aepg_detail in f_a:
        aepg_name = aepg_detail[0]
        for epg_list in aepg_detail[1]:
            epg_name = epg_list[0]
            provided_contract_list = epg_list[1]
            consumed_contract_list = epg_list[2]
            for p_c in provided_contract_list:
                text += '{:<25} {:<25} {:^17} {:<20} \n'.format(aepg_name, epg_name, 'P', p_c)
            for c_c in consumed_contract_list:
                text += '{:<25} {:<25} {:^17} {:<20} \n'.format(aepg_name, epg_name, 'C', c_c)
    return text


def export_to_xlsx(export_f_n, f_a, f_c, f_f):
    # print(json.dumps(f_a, indent=4))
    row = 0
    col = 0
    workbook = xlsxwriter.Workbook(export_f_n)
    worksheet = workbook.add_worksheet('AEPg-to-filterEntry')
    bold = workbook.add_format({'bold': True})
    worksheet.write(row, col, 'AEPg Name', bold)
    worksheet.write(row, col + 1, 'EPG Name', bold)
    worksheet.write(row, col + 2, 'Provide/Consume', bold)
    worksheet.write(row, col + 3, 'Contract Name', bold)
    worksheet.write(row, col + 4, 'Subject Name', bold)
    worksheet.write(row, col + 5, 'BiDir', bold)
    worksheet.write(row, col + 6, 'Action', bold)
    worksheet.write(row, col + 7, 'Filter Name', bold)
    worksheet.write(row, col + 8, 'Filter Entry Name', bold)
    worksheet.write(row, col + 9, 'Proto', bold)
    worksheet.write(row, col + 10, 'D.F.Port', bold)
    worksheet.write(row, col + 11, 'D.T.Port', bold)
    worksheet.write(row, col + 12, 'StFull', bold)
    row += 1

    for aepg_detail in sorted(f_a):
        aepg_name = aepg_detail[0]

        for epg_list in sorted(aepg_detail[1]):
            epg_name = epg_list[0]
            provided_contract_list = epg_list[1]
            consumed_contract_list = epg_list[2]

            for p_c in sorted(provided_contract_list):
                if p_c in f_c.keys():
                    for subject in f_c[p_c]:
                        fe_list = list(get_filter(f_f, subject[3]))
                        for f_e in fe_list:
                            if f_e[1] == 'unspecified':
                                f_e[1] = 'any'
                            if f_e[2] == 'unspecified':
                                f_e[2] = 'any'
                            if f_e[3] == 'unspecified':
                                f_e[3] = 'any'

                            worksheet.write(row, col, aepg_name)
                            worksheet.write(row, col + 1, epg_name)
                            worksheet.write(row, col + 2, 'P')
                            worksheet.write(row, col + 3, p_c)
                            worksheet.write(row, col + 4, subject[0])
                            worksheet.write(row, col + 5, subject[1])
                            worksheet.write(row, col + 6, subject[2])
                            worksheet.write(row, col + 7, subject[3])
                            worksheet.write(row, col + 8, f_e[0])
                            worksheet.write(row, col + 9, f_e[1])
                            worksheet.write(row, col + 10, f_e[2])
                            worksheet.write(row, col + 11, f_e[3])
                            worksheet.write(row, col + 12, f_e[4])
                            row += 1
                else:
                    worksheet.write(row, col, aepg_name)
                    worksheet.write(row, col + 1, epg_name)
                    worksheet.write(row, col + 2, 'P')
                    worksheet.write(row, col + 3, p_c)
                    worksheet.write(row, col + 4, 'missing contract')
                    worksheet.write(row, col + 5, '')
                    worksheet.write(row, col + 6, '')
                    worksheet.write(row, col + 7, '')
                    worksheet.write(row, col + 8, '')
                    worksheet.write(row, col + 9, '')
                    worksheet.write(row, col + 10, '')
                    worksheet.write(row, col + 11, '')
                    worksheet.write(row, col + 12, '')
                    row += 1

            for c_c in sorted(consumed_contract_list):
                if c_c in f_c.keys():
                    for subject in f_c[c_c]:
                        fe_list = list(get_filter(f_f, subject[3]))
                        for f_e in fe_list:
                            if f_e[1] == 'unspecified':
                                f_e[1] = 'any'
                            if f_e[2] == 'unspecified':
                                f_e[2] = 'any'
                            if f_e[3] == 'unspecified':
                                f_e[3] = 'any'

                            worksheet.write(row, col, aepg_name)
                            worksheet.write(row, col + 1, epg_name)
                            worksheet.write(row, col + 2, 'C')
                            worksheet.write(row, col + 3, c_c)
                            worksheet.write(row, col + 4, subject[0])
                            worksheet.write(row, col + 5, subject[1])
                            worksheet.write(row, col + 6, subject[2])
                            worksheet.write(row, col + 7, subject[3])
                            worksheet.write(row, col + 8, f_e[0])
                            worksheet.write(row, col + 9, f_e[1])
                            worksheet.write(row, col + 10, f_e[2])
                            worksheet.write(row, col + 11, f_e[3])
                            worksheet.write(row, col + 12, f_e[4])
                            row += 1
                else:
                    worksheet.write(row, col, aepg_name)
                    worksheet.write(row, col + 1, epg_name)
                    worksheet.write(row, col + 2, 'C')
                    worksheet.write(row, col + 3, c_c)
                    worksheet.write(row, col + 4, 'missing contract')
                    worksheet.write(row, col + 5, '')
                    worksheet.write(row, col + 6, '')
                    worksheet.write(row, col + 7, '')
                    worksheet.write(row, col + 8, '')
                    worksheet.write(row, col + 9, '')
                    worksheet.write(row, col + 10, '')
                    worksheet.write(row, col + 11, '')
                    worksheet.write(row, col + 12, '')
                    row += 1

    workbook.close()


def get_filter(f_f, f_n):
    if f_n in f_f.keys():
        return f_f[f_n]
    else:
        return [['na', 'na', 'na', 'na', 'na']]


def main():
    static_data = input('\nUse static data (y/n): ')

    if static_data.lower() == 'n':
        host = input('APIC host to connect to: ')
        print('If you are using external APIC authentication use format \'apic:realm\\\\user\'')
        username = input('Username: ')
        password = input('Password: ')

        print('Logging in...')

        try:
            token = login(host, username, password)
        except Exception as e:
            print(e)
            sys.exit(1)

        if token is not None:
            print('Logging Successful\nGetting tenants list...')
            get_tenants(host, token)
        else:
            print('Logging Failed')
            sys.exit(1)

        start_login_expired_timer = time()
        ten = input('\nSelect tenant name: ')
        if ten not in tenants:
            print('\nInput Error. Select a tenant from the list.\n')
            sys.exit(1)

        end_login_expired_timer = time()

        if end_login_expired_timer - start_login_expired_timer >= 55:
            print('Expired token, re logging ...')
            token = login(host, username, password)
            if token is not None:
                print('Logging Successful\n')
                get_tenants(host, token)
            else:
                print('Logging Failed')
                sys.exit(1)

        print('Downloading tenant detail...')
        timer_download = perf_counter()
        config = get_tenant(host, token, ten)
        print('\nDownload time: {:0.4f} seconds\n'.format(perf_counter() - timer_download))

        filename = '{}-{}-{}.json'.format(host, ten, date.today())

        print(f'Saving tenant to {filename}\n')
        with open(filename, 'w') as fp:
            json.dump(config, fp)

    elif static_data.lower() == 'y':
        file_list = []
        print('\nUsing local files:\n')
        for file in os.listdir('./'):
            if file.endswith(".json"):
                file_list.append(file)
                print(file)
        filename = input('\nSelect file name: ')

        if filename not in file_list:
            print('Invalid file name')
            sys.exit(1)

        # filename = 'co-TENANT-DTV' + '.json'
        print(f'\nReading tenant to {filename}\n')
        with open(filename, 'r') as fp:
            config = json.load(fp)

        # print(json.dumps(config, indent=4))

    else:
        print('Invalid input')
        sys.exit(1)

    print('Processing...')
    timer_processing = perf_counter()

    full_aep, num_aepg, num_epg, full_contract, num_con, full_filter, num_fil = extract_data(config)

    # print(json.dumps(full_aep, indent=4))

    print('\nProcessing time: {:0.4f} seconds\n'.format(perf_counter() - timer_processing))

    export_filename = '{}.xlsx'.format(filename.split('.')[0])

    select_output = input('Select output type:\n\n'
                          '1.- to screen Contract-Filter-FilterEntry\n'
                          '2.- to screen AP-EPG-Contract\n'
                          '3.- to xls AP-EPG-Contract-Filter-FilterEntry \'{}\'\n\n'
                          'Select option: '.format(export_filename))

    if str(select_output) == '1':
        timer_parsing = perf_counter()
        final_text = nice_print_contracts(full_contract, full_filter)
        print(final_text)
        print('\nParsing time: {:0.4f} seconds\n'.format(perf_counter() - timer_parsing))

        if (len(full_contract) == num_con) and (len(full_filter) == num_fil):
            double_check = 'OK'
        else:
            double_check = 'FAIL'
        print(f'Doble check counters: {double_check}\n')
        print(f'Input file:\n'
              f'#Contracts: {len(full_contract)}\n'
              f'#Filters: {len(full_filter)}\n')
        print(f'Script:\n'
              f'#Contracts: {num_con}\n'
              f'#Filters: {num_fil}\n')

    elif str(select_output) == '2':
        timer_parsing = perf_counter()
        final_text = nice_print_aepg(full_aep)
        print(final_text)
        print('\nParsing time: {:0.4f} seconds\n'.format(perf_counter() - timer_parsing))
        count = 0
        for aep in full_aep:
            for epg in aep[1]:
                count += 1
        if (len(full_aep) == num_aepg) and (count == num_epg):
            double_check = 'OK'
        else:
            double_check = 'FAIL'

        print(f'Doble check counters: {double_check}\n')
        print(f'Input file:\n'
              f'#AEPg: {len(full_aep)}\n'
              f'#EPG: {count}\n')
        print(f'Script:\n'
              f'#AEPg: {num_aepg}\n'
              f'#EPG: {num_epg}\n')

    elif str(select_output) == '3':
        timer_file_creation = perf_counter()
        export_to_xlsx(export_filename, full_aep, full_contract, full_filter)
        count = 0
        for aep in full_aep:
            for epg in aep[1]:
                count += 1

        if (len(full_aep) == num_aepg) and (count == num_epg):
            double_check = 'OK'
        else:
            double_check = 'FAIL'
        print(f'\nDoble check counters: {double_check}\n')
        print(f'Input file:\n'
              f'#AEPg: {len(full_aep)}\n'
              f'#EPG: {count}\n'
              f'#Contracts: {len(full_contract)}\n'
              f'#Filters: {len(full_filter)}\n')
        print(f'Script:\n'
              f'#AEPg: {num_aepg}\n'
              f'#EPG: {num_epg}\n'
              f'#Contracts: {num_con}\n'
              f'#Filters: {num_fil}\n')

        print(f'File save as: {export_filename}')
        print('\nCreating file time: {:0.4f} seconds\n'.format(perf_counter() - timer_file_creation))
    else:
        print('\nInvalid option\n')


if __name__ == '__main__':
    main()
