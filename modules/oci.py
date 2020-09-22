# Modules to work with OCI

import json
import os
import socket
from pprint import pprint

import modules.aci as aci

# ACI port names sometimes don't match the RFC.
# Add to this dictionary different port number and names
_EXTRA_PORT_NUMBERS = {
    'ftpData': '20',
}


def identify_port_number(aci_filter_entry):
    if aci_filter_entry[2] == 'unspecified':
        min_p = '1'
    else:
        try:
            min_p = str(socket.getservbyname(aci_filter_entry[2]))
        except OSError:
            if aci_filter_entry[2] in _EXTRA_PORT_NUMBERS.keys():
                min_p = _EXTRA_PORT_NUMBERS[aci_filter_entry[2]]
            else:
                min_p = aci_filter_entry[2]

    if aci_filter_entry[3] == 'unspecified':
        max_p = '65535'
    else:
        try:
            max_p = str(socket.getservbyname(aci_filter_entry[3]))
        except OSError:
            if aci_filter_entry[2] in _EXTRA_PORT_NUMBERS.keys():
                max_p = _EXTRA_PORT_NUMBERS[aci_filter_entry[2]]
            else:
                max_p = aci_filter_entry[3]

    return min_p, max_p


def add_tcp_udp_rule(aci_filter_entry, oci_nsg_full_dict, oci_display_name, current_oci_nsg_id, ocid_other_nsg_end_id,
                     oci_direction, oci_nsg_rule_type):

    if aci_filter_entry[1] == '6':
        protocol = '6'  # TCP
        options = 'tcp_options'
    else:
        protocol = '17'  # UDP
        options = 'udp_options'

    if oci_direction == 'INGRESS':
        direction = 'source'
        direction_type = 'source_type'
    else:
        direction = 'destination'
        direction_type = 'destination_type'

    stateless = 'false' if aci_filter_entry[4] == 'yes' else 'true'
    min_p, max_p = identify_port_number(aci_filter_entry)

    if oci_display_name not in oci_nsg_full_dict.keys():
        oci_nsg_full_dict[oci_display_name] = {'resources': []}

    if ocid_other_nsg_end_id == 'ANY':
        src_dst = '0.0.0.0/0'
    else:
        src_dst = ocid_other_nsg_end_id

    oci_nsg_full_dict[oci_display_name]['resources'].append(
        {
            'network_security_group_id': current_oci_nsg_id,
            'direction': oci_direction,
            'protocol': protocol,
            options: {"destination_port_range": {
                "min": min_p,
                "max": max_p
            }
            },
            direction: src_dst,
            'stateless': stateless,
            direction_type: oci_nsg_rule_type
        }
    )


def add_icmp_rule(aci_filter_entry, oci_nsg_full_dict, oci_display_name, current_oci_nsg_id, ocid_other_nsg_end_id,
                  oci_direction, oci_nsg_rule_type):
    protocol = '1'
    stateless = 'false' if aci_filter_entry[4] == 'yes' else 'true'

    if oci_direction == 'INGRESS':
        direction = 'source'
        direction_type = 'source_type'
    else:
        direction = 'destination'
        direction_type = 'destination_type'

    if ocid_other_nsg_end_id == 'ANY':
        src_dst = '0.0.0.0/0'
    else:
        src_dst = ocid_other_nsg_end_id

    if oci_display_name not in oci_nsg_full_dict.keys():
        oci_nsg_full_dict[oci_display_name] = {'resources': []}

    oci_nsg_full_dict[oci_display_name]['resources'].append(
        {
            'network_security_group_id': current_oci_nsg_id,
            'direction': oci_direction,
            'protocol': protocol,
            direction: src_dst,
            'stateless': stateless,
            direction_type: oci_nsg_rule_type
        }
    )


def add_all_protocols_rule(aci_filter_entry, oci_nsg_full_dict, oci_display_name, current_oci_nsg_id,
                           ocid_other_nsg_end_id, oci_direction, oci_nsg_rule_type):
    protocol = 'all'
    stateless = 'false' if aci_filter_entry[4] == 'yes' else 'true'

    if oci_direction == 'INGRESS':
        direction = 'source'
        direction_type = 'source_type'
    else:
        direction = 'destination'
        direction_type = 'destination_type'

    if oci_display_name not in oci_nsg_full_dict.keys():
        oci_nsg_full_dict[oci_display_name] = {'resources': []}

    oci_nsg_full_dict[oci_display_name]['resources'].append(
        {
            'network_security_group_id': current_oci_nsg_id,
            'direction': oci_direction,
            'protocol': protocol,
            direction: ocid_other_nsg_end_id,
            'stateless': stateless,
            direction_type: oci_nsg_rule_type
        }
    )


def build_add_rule(aci_filter_entry, aci_source_epg, aci_other_end_epg, aci_consumed_contract_name, aci_filter_name,
                   oci_full_nsg_dict, oci_nsg_display_name, current_oci_nsg_id, ocid_other_nsg_end_id, oci_direction,
                   oci_nsg_rule_type):

    if aci_other_end_epg == 'ANY':
        src_dst = '0.0.0.0/0'
        ocid_src_dst = '0.0.0.0/0'
    else:
        src_dst = aci_other_end_epg
        ocid_src_dst = ocid_other_nsg_end_id

    if aci_filter_entry[1] == 'tcp' or aci_filter_entry[1] == 'udp':
        add_tcp_udp_rule(aci_filter_entry, oci_full_nsg_dict, oci_nsg_display_name,
                         current_oci_nsg_id, ocid_src_dst, oci_direction, oci_nsg_rule_type)

    elif aci_filter_entry[1] == 'icmp':
        add_icmp_rule(aci_filter_entry, oci_full_nsg_dict, oci_nsg_display_name,
                      current_oci_nsg_id, ocid_src_dst, oci_direction, oci_nsg_rule_type)

    elif aci_filter_entry[1] == 'unspecified':
        add_all_protocols_rule(aci_filter_entry, oci_full_nsg_dict,
                               oci_nsg_display_name, current_oci_nsg_id,
                               ocid_src_dst, oci_direction, oci_nsg_rule_type)

    else:
        print('\nWARNING: Skipping rule. Missing filter or protocol not recognized '
              'at filter: ' + str(aci_filter_entry))
        if oci_direction == 'EGRESS':
            print('EPG Consumer: ' + aci_source_epg)
            print('EPG Provider: ' + src_dst)
        else:
            print('EPG Provider: ' + aci_source_epg)
            print('EPG Consumer: ' + src_dst)
        print('Contract: ' + str(aci_consumed_contract_name))
        print('Filter Name: ' + str(aci_filter_name))


def export_to_oci_format(aci_full_aep_list, aci_full_contracts_dict, aci_full_filters_dict,
                         _default_permit_all_egress_and_icmp_in, _acronysm_to_skip_in_epg_name):
    oci_full_nsg_dict = {}
    for aci_aep in aci_full_aep_list:
        for aci_epg in aci_aep[1]:
            if aci.skip_aci_epg_name(aci_epg[0], _acronysm_to_skip_in_epg_name):
                continue
            else:
                aci_source_epg = aci_epg[0]
                oci_nsg_display_name = aci_aep[0] + "-" + aci_source_epg

                if _default_permit_all_egress_and_icmp_in:
                    destination = 'ANY'
                    aci_filter_entry = [None, 'unspecified', None, None, 'false']
                    aci_consumed_contract_name = None
                    filter_name = None
                    oci_nsg_rule_type = 'CIDR_BLOCK'

                    current_oci_nsg_id = "${oci_core_network_security_group." \
                                         "aci_exported_nsg_" + oci_nsg_display_name + ".id}"
                    ocid_destination = "${oci_core_network_security_group." \
                                       "aci_exported_nsg_" + destination + ".id}"

                    oci_direction = 'EGRESS'

                    build_add_rule(aci_filter_entry, aci_source_epg, destination,
                                   aci_consumed_contract_name, filter_name, oci_full_nsg_dict,
                                   oci_nsg_display_name, current_oci_nsg_id, ocid_destination,
                                   oci_direction, oci_nsg_rule_type)

                    source = 'ANY'
                    oci_direction = 'INGRESS'
                    aci_filter_entry = [None, 'icmp', None, None, 'false']

                    build_add_rule(aci_filter_entry, aci_source_epg, source,
                                   aci_consumed_contract_name, filter_name, oci_full_nsg_dict,
                                   oci_nsg_display_name, current_oci_nsg_id, ocid_destination,
                                   oci_direction, oci_nsg_rule_type)

                else:
                    for aci_consumed_contract_name in aci_epg[2]:
                        if aci_consumed_contract_name not in aci_full_contracts_dict.keys():
                            print('\nWARNING: Skipping rule. Missing contract: ' + aci_consumed_contract_name)
                            print('EPG Consumer: ' + aci_source_epg)

                        else:
                            for aci_subject in aci_full_contracts_dict[aci_consumed_contract_name]:
                                is_bidir = aci_subject[1]
                                aci_filter_list = aci.get_filter(aci_full_filters_dict, aci_subject[3])

                                for aci_filter_entry in aci_filter_list:

                                    aci_all_providers = aci.get_consumer_epg(aci_full_aep_list,
                                                                             aci_consumed_contract_name,
                                                                             _acronysm_to_skip_in_epg_name)

                                    if len(aci_all_providers) != 0:
                                        if oci_nsg_display_name not in oci_full_nsg_dict.keys():
                                            oci_full_nsg_dict[oci_nsg_display_name] = {'resources': []}

                                        for aci_provider in aci_all_providers:
                                            current_oci_nsg_id = "${oci_core_network_security_group." \
                                                                 "aci_exported_nsg_" + oci_nsg_display_name + ".id}"
                                            ocid_destination = "${oci_core_network_security_group." \
                                                               "aci_exported_nsg_" + aci_provider + ".id}"
                                            oci_direction = 'EGRESS'
                                            oci_nsg_rule_type = 'NETWORK_SECURITY_GROUP'

                                            build_add_rule(aci_filter_entry, aci_source_epg, aci_provider,
                                                           aci_consumed_contract_name, aci_subject[3],
                                                           oci_full_nsg_dict,
                                                           oci_nsg_display_name, current_oci_nsg_id, ocid_destination,
                                                           oci_direction, oci_nsg_rule_type)

                                    else:
                                        print('\nWARNING: Skipping rule. No providers'
                                              ' for contract: ' + aci_consumed_contract_name)
                                        print('EPG Consumer: ' + aci_source_epg)

                for aci_provided_contract_name in aci_epg[1]:
                    if aci_provided_contract_name not in aci_full_contracts_dict.keys():
                        print('\nWARNING: Skipping rule. Missing contract: ' + aci_provided_contract_name)
                        print('EPG Provider: ' + aci_source_epg)

                    else:
                        for aci_subject in aci_full_contracts_dict[aci_provided_contract_name]:
                            is_bidir = aci_subject[1]
                            aci_filter_list = aci.get_filter(aci_full_filters_dict, aci_subject[3])

                            for aci_filter_entry in aci_filter_list:

                                aci_consumers = aci.get_consumer_epg(aci_full_aep_list, aci_provided_contract_name,
                                                                     _acronysm_to_skip_in_epg_name)
                                if len(aci_consumers) != 0:
                                    if oci_nsg_display_name not in oci_full_nsg_dict.keys():
                                        oci_full_nsg_dict[oci_nsg_display_name] = {'resources': []}

                                    for aci_consumer in aci_consumers:
                                        current_oci_nsg_id = "${oci_core_network_security_group." \
                                                             "aci_exported_nsg_" + oci_nsg_display_name + ".id}"
                                        ocid_destination = "${oci_core_network_security_group." \
                                                           "aci_exported_nsg_" + aci_consumer + ".id}"
                                        oci_direction = 'INGRESS'
                                        oci_nsg_rule_type = 'NETWORK_SECURITY_GROUP'

                                        build_add_rule(aci_filter_entry, aci_source_epg, aci_consumer,
                                                       aci_provided_contract_name, aci_subject[3], oci_full_nsg_dict,
                                                       oci_nsg_display_name, current_oci_nsg_id, ocid_destination,
                                                       oci_direction, oci_nsg_rule_type)

                                else:
                                    print('\nWARNING: Skipping rule. No consumer for '
                                          'contract: ' + aci_provided_contract_name)
                                    print('EPG Provider: ' + aci_source_epg)

    return oci_full_nsg_dict


def save_oci_files(oci_nsg, _export_to_dir, _nsg_over_allowed_rules):
    ingress_nsg_with_exceeding_rules = {}
    egress_nsg_with_exceeding_rules = {}
    rule_entry_count = 0
    if not os.path.exists(_export_to_dir):
        os.makedirs(_export_to_dir)
    for nsg_name, resources in oci_nsg.items():
        with open(_export_to_dir + nsg_name + '.tf.json', 'w') as file:
            item = "aci_exported_nsg_" + nsg_name
            nsg_dict = {"resource": [{
                "oci_core_network_security_group": {
                    item: {
                        "compartment_id": "${var.compartment_id}",
                        "vcn_id": "${var.vcn_id}",
                        "display_name": nsg_name
                    }
                }
            }
            ]
            }
            rule_entry_count += 1

            temp = {'oci_core_network_security_group_security_rule': []}

            ingress_rule_number_counter = 1
            egress_rule_number_counter = 1
            for resource in resources['resources']:
                rule_entry_count += 1
                if resource['direction'] == 'INGRESS':
                    item_sr = item + "_security_rule_IN_" + str(ingress_rule_number_counter)
                    temp["oci_core_network_security_group_security_rule"].append({item_sr: resource})
                    ingress_rule_number_counter += 1

                    if ingress_rule_number_counter >= _nsg_over_allowed_rules:
                        if item not in ingress_nsg_with_exceeding_rules.keys():
                            ingress_nsg_with_exceeding_rules[item] = _nsg_over_allowed_rules
                        else:
                            ingress_nsg_with_exceeding_rules[item] = ingress_rule_number_counter

                        print(f'\nERROR maximum number of 120 NSG Ingress security rules per'
                              f' NSG exceeded ! - {ingress_rule_number_counter}\n')
                        print('Rule: ')
                        pprint(item_sr)
                        print('Resource: ')
                        pprint(resource)

                elif resource['direction'] == 'EGRESS':
                    item_sr = item + "_security_rule_OUT_" + str(egress_rule_number_counter)
                    temp["oci_core_network_security_group_security_rule"].append({item_sr: resource})
                    egress_rule_number_counter += 1

                    if egress_rule_number_counter >= 121:
                        if item not in egress_nsg_with_exceeding_rules.keys():
                            egress_nsg_with_exceeding_rules[item] = 121
                        else:
                            egress_nsg_with_exceeding_rules[item] = egress_rule_number_counter

                        print(f'\nERROR maximum number of 120 NSG Egress security rules per'
                              f' NSG exceeded ! - {egress_rule_number_counter}\n')
                        print('Rule: ')
                        pprint(item_sr)
                        print('Resource: ')
                        pprint(resource)

            nsg_dict['resource'].append(temp)
            json.dump(nsg_dict, file)

    if len(ingress_nsg_with_exceeding_rules) >= _nsg_over_allowed_rules:
        print('\nIngress NSG with more than 120 rules\n')
        pprint(ingress_nsg_with_exceeding_rules)

    if len(egress_nsg_with_exceeding_rules) >= _nsg_over_allowed_rules:
        print('\nEngress NSG with more than 120 rules\n')
        pprint(egress_nsg_with_exceeding_rules)

    print(f'\nComposite rule entries: {rule_entry_count}')
