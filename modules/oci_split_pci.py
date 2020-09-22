# Modules to work with OCI

import json
import socket
from pprint import pprint
import python.aci_to_oci_w_terraform.modules.aci as aci

# ACI port names sometimes don't match the RFC.
# Add to this dictionary different port number and names
_EXTRA_PORT_NUMBERS = {
    'ftpData': '20',
}


def identify_port_number(aci_filter_entry):
    if aci_filter_entry[2] == 'unspecified':
        min_p = '0'
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
                     oci_direction):
    if aci_filter_entry[1] == '6':
        protocol = '6'  # TCP
        options = 'tcp_options'
    else:
        protocol = '17'  # UDP
        options = 'udp_options'

    stateless = 'false' if aci_filter_entry[4] == 'yes' else 'true'
    min_p, max_p = identify_port_number(aci_filter_entry)

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
            'destination': ocid_other_nsg_end_id,
            'stateless': stateless,
            'destination_type': 'NETWORK_SECURITY_GROUP'
        }
    )


def add_icmp_rule(aci_filter_entry, oci_nsg_full_dict, oci_display_name, current_oci_nsg_id, ocid_other_nsg_end_id,
                  oci_direction):
    protocol = '1'
    stateless = 'false' if aci_filter_entry[4] == 'yes' else 'true'

    oci_nsg_full_dict[oci_display_name]['resources'].append(
        {
            'network_security_group_id': current_oci_nsg_id,
            'direction': oci_direction,
            'protocol': protocol,
            'destination': ocid_other_nsg_end_id,
            'stateless': stateless,
            'destination_type': 'NETWORK_SECURITY_GROUP'
        }
    )


def add_all_protocols_rule(aci_filter_entry, oci_nsg_full_dict, oci_display_name, current_oci_nsg_id,
                           ocid_other_nsg_end_id, oci_direction):
    protocol = 'all'
    stateless = 'false' if aci_filter_entry[4] == 'yes' else 'true'

    oci_nsg_full_dict[oci_display_name]['resources'].append(
        {
            'network_security_group_id': current_oci_nsg_id,
            'direction': oci_direction,
            'protocol': protocol,
            'destination': ocid_other_nsg_end_id,
            'stateless': stateless,
            'destination_type': 'NETWORK_SECURITY_GROUP'
        }
    )


def build_add_rule(aci_filter_entry, aci_source_epg, aci_other_end_epg, aci_consumed_contract_name, aci_filter_name,
                   oci_full_nsg_dict, oci_nsg_display_name, current_oci_nsg_id, ocid_other_nsg_end_id, oci_direction):
    if aci_filter_entry[1] == 'tcp' or aci_filter_entry[1] == 'udp':
        add_tcp_udp_rule(aci_filter_entry, oci_full_nsg_dict, oci_nsg_display_name,
                         current_oci_nsg_id, ocid_other_nsg_end_id, oci_direction)

    elif aci_filter_entry[1] == 'icmp':
        add_icmp_rule(aci_filter_entry, oci_full_nsg_dict, oci_nsg_display_name,
                      current_oci_nsg_id, ocid_other_nsg_end_id, oci_direction)

    elif aci_filter_entry[1] == 'unspecified':
        add_all_protocols_rule(aci_filter_entry, oci_full_nsg_dict,
                               oci_nsg_display_name, current_oci_nsg_id,
                               ocid_other_nsg_end_id, oci_direction)

    else:
        print('\nWARNING: Skipping rule. Missing filter or protocol not recognized '
              'at filter: ' + str(aci_filter_entry))
        if oci_direction == 'EGRESS':
            print('EPG Consumer: ' + aci_source_epg)
            print('EPG Provider: ' + aci_other_end_epg)
        else:
            print('EPG Provider: ' + aci_source_epg)
            print('EPG Consumer: ' + aci_other_end_epg)
        print('Contract: ' + aci_consumed_contract_name)
        print('Filter Name: ' + aci_filter_name)


def export_to_oci(aci_full_aep_list, aci_full_contracts_dict, aci_full_filters_dict):
    oci_full_nsg_dict = {}
    for aci_aep in aci_full_aep_list:
        for aci_epg in aci_aep[1]:
            aci_source_epg = aci_epg[0]
            oci_nsg_display_name = aci_aep[0] + "-" + aci_source_epg

            for aci_consumed_contract_name in aci_epg[2]:
                if aci_consumed_contract_name not in aci_full_contracts_dict.keys():
                    print('\nWARNING: Skipping rule. Missing contract: ' + aci_consumed_contract_name)
                    print('EPG Consumer: ' + aci_source_epg)

                else:
                    for aci_subject in aci_full_contracts_dict[aci_consumed_contract_name]:
                        is_bidir = aci_subject[1]
                        aci_filter_list = aci.get_filter(aci_full_filters_dict, aci_subject[3])

                        for aci_filter_entry in aci_filter_list:

                            aci_all_providers = aci.get_consumer_epg(aci_full_aep_list, aci_consumed_contract_name)

                            if len(aci_all_providers) != 0:
                                if oci_nsg_display_name not in oci_full_nsg_dict.keys():
                                    oci_full_nsg_dict[oci_nsg_display_name] = {'resources': []}

                                for aci_provider in aci_all_providers:
                                    current_oci_nsg_id = "${oci_core_network_security_group." \
                                                         "aci_exported_nsg_" + oci_nsg_display_name + ".id}"
                                    ocid_destination = "${oci_core_network_security_group." \
                                                       "aci_exported_nsg_" + aci_provider + ".id}"
                                    oci_direction = 'EGRESS'

                                    build_add_rule(aci_filter_entry, aci_source_epg, aci_provider,
                                                   aci_consumed_contract_name, aci_subject[3], oci_full_nsg_dict,
                                                   oci_nsg_display_name, current_oci_nsg_id, ocid_destination,
                                                   oci_direction)

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

                            aci_consumers = aci.get_consumer_epg(aci_full_aep_list, aci_provided_contract_name)
                            if len(aci_consumers) != 0:
                                if oci_nsg_display_name not in oci_full_nsg_dict.keys():
                                    oci_full_nsg_dict[oci_nsg_display_name] = {'resources': []}

                                for aci_consumer in aci_consumers:
                                    current_oci_nsg_id = "${oci_core_network_security_group." \
                                                         "aci_exported_nsg_" + oci_nsg_display_name + ".id}"
                                    ocid_destination = "${oci_core_network_security_group." \
                                                       "aci_exported_nsg_" + aci_consumer + ".id}"
                                    oci_direction = 'INGRESS'

                                    build_add_rule(aci_filter_entry, aci_source_epg, aci_consumer,
                                                   aci_provided_contract_name, aci_subject[3], oci_full_nsg_dict,
                                                   oci_nsg_display_name, current_oci_nsg_id, ocid_destination,
                                                   oci_direction)

                            else:
                                print('\nWARNING: Skipping rule. No consumer for '
                                      'contract: ' + aci_provided_contract_name)
                                print('EPG Provider: ' + aci_source_epg)

    return oci_full_nsg_dict


def save_oci_files(oci_nsg, _export_to_dir):
    ingress_nsg_with_exceeding_rules = {}
    egress_nsg_with_exceeding_rules = {}
    rule_entry_count = 0
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

                    if ingress_rule_number_counter >= 121:
                        if item not in ingress_nsg_with_exceeding_rules.keys():
                            ingress_nsg_with_exceeding_rules[item] = 121
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

    print('\nIngress NSG with more than 120 rules\n')
    pprint(ingress_nsg_with_exceeding_rules)
    print('\nEngress NSG with more than 120 rules\n')
    pprint(egress_nsg_with_exceeding_rules)
    print(f'\nRule entries: {rule_entry_count}\n')
