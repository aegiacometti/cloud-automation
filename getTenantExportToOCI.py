#!/usr/bin/env python3

# Script to connect to an Cisco ACI APIC, download a Tenant and export information
# to OCI and Terraform data structures.
# Cleaning rules and adaptations

import json
import os
import sys
import getpass
from datetime import date
from time import time, perf_counter

import modules.aci as aci
import modules.oci as oci

_ACI_RELOGIN_TIMER = 55
_DATA_DIR = './data/'
_EXPORT_TO_DIR = './export-OCI/'
_NSG_OVER_ALLOWED_RULES = 121
_DEFAULT_PERMIT_ALL_EGRESS_AND_ICMP_IN = True
_ACRONYSM_TO_SKIP_IN_EPG_NAME = ['-BD', 'VLAN']


def list_available_configurations():
    file_list = []
    for file in os.listdir(_DATA_DIR):
        if file.endswith(".json"):
            file_list.append(file)
            print(file)
    return file_list


def use_pre_downloaded_config(file_list):
    filename = input('\nSelect file name: ')

    if filename not in file_list:
        print('Invalid file name')
        sys.exit(1)

    print(f'\nReading tenant {filename}\n')
    with open(_DATA_DIR + filename, 'r') as file_write:
        aci_tenant_config = json.load(file_write)

    # print(json.dumps(config, indent=4))
    return aci_tenant_config


def download_config():
    print('\n[ Enter APIC login info ]\n')
    host = input('APIC host IP address: ')
    print('If you are using external APIC authentication use format \'apic:realm\\\\user\'')
    username = input('Username: ')
    password = getpass.getpass(prompt='Password: ', stream=None)

    print('\nLogging in...')

    try:
        token = aci.login(host, username, password)
    except Exception as e:
        print(e)
        sys.exit(1)

    if token is not None:
        print('Logging Successful\nGetting tenants list...')
        tenants = aci.get_tenants(host, token)
    else:
        print('Logging Failed')
        sys.exit(1)

    start_login_expired_timer = time()
    ten = input('\nSelect tenant name: ')
    if ten not in tenants:
        print('\nInput Error. Select a tenant from the list.\n')
        sys.exit(1)

    end_login_expired_timer = time()

    if end_login_expired_timer - start_login_expired_timer >= _ACI_RELOGIN_TIMER:
        print('Expired token, re logging ...')
        token = aci.login(host, username, password)
        if token is not None:
            print('Logging Successful\n')
        else:
            print('Logging Failed')
            sys.exit(1)

    print('\nDownloading tenant detail...')
    timer_download = perf_counter()
    aci_tenant_config = aci.get_tenant(host, token, ten)
    print('\nDownload time: {:0.4f} seconds\n'.format(perf_counter() - timer_download))

    filename = '{}-{}-{}.json'.format(host, ten, date.today())

    print(f'Saving tenant to {filename}\n')
    with open(_DATA_DIR + filename, 'w') as file_write:
        json.dump(aci_tenant_config, file_write)

    return aci_tenant_config


def main():
    print('[ INIT ]\n')
    print('[ Select configuration ]\n')
    file_list = list_available_configurations()

    static_data = input('\nUse static pre downloaded data (y/n): ')

    if static_data.lower() == 'y':
        aci_tenant_config = use_pre_downloaded_config(file_list)

    elif static_data.lower() == 'n':
        aci_tenant_config = download_config()

    else:
        print('Invalid input')
        sys.exit(1)

    print('\n[ Process Cisco ACI Tenant ]\n')
    input('Press any key to start...\n')
    print('Processing...')
    timer_processing = perf_counter()
    full_aep, num_aepg, num_epg, full_contract, num_con, full_filter, num_fil = aci.extract_data(aci_tenant_config)
    # print(json.dumps(full_aep, indent=4))
    print('\nProcessing time: {:0.4f} seconds\n'.format(perf_counter() - timer_processing))

    print('\n[ Translate configuration to Oracle OCI ]\n')
    input('Press any key to start...\n')
    print('Translating to OCI structure...')
    timer_processing_to_oci = perf_counter()
    oci_dict = oci.export_to_oci_format(full_aep, full_contract, full_filter, _DEFAULT_PERMIT_ALL_EGRESS_AND_ICMP_IN,
                                        _ACRONYSM_TO_SKIP_IN_EPG_NAME)
    print('\nProcessing time: {:0.4f} seconds\n'.format(perf_counter() - timer_processing_to_oci))

    print('\n\n[ Saving OCI files ]\n')
    timer_processing_to_oci = perf_counter()
    oci.save_oci_files(oci_dict, _EXPORT_TO_DIR, _NSG_OVER_ALLOWED_RULES)
    print('\nFiles created')
    print('\nProcessing time: {:0.4f} seconds\n'.format(perf_counter() - timer_processing_to_oci))


if __name__ == '__main__':
    main()
