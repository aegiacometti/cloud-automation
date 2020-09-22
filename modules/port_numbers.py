import socket


def identify_port_number(aci_filter_entry):
    if aci_filter_entry[2] == 'unspecified':
        min_p = '0'
    else:
        try:
            min_p = str(socket.getservbyname(aci_filter_entry[2]))
        except OSError:
            if aci_filter_entry[2] == 'ftpData':
                min_p = '20'
            else:
                min_p = aci_filter_entry[2]

    if aci_filter_entry[3] == 'unspecified':
        max_p = '65535'
    else:
        try:
            max_p = str(socket.getservbyname(aci_filter_entry[3]))
        except OSError:
            if aci_filter_entry[2] == 'ftpData':
                max_p = '20'
            else:
                max_p = aci_filter_entry[3]

    return min_p, max_p
