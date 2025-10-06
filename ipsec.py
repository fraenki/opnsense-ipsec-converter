#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import uuid
from itertools import product
import os
import re
import ipaddress

# --- Configuration ---
# Path to the original OPNsense configuration file
INPUT_CONFIG_PATH = 'config.old.xml'

# Path for the newly generated configuration file
OUTPUT_CONFIG_PATH = 'config.new.xml'

# --- Helper Functions ---
def get_text_from_element(element, tag, default=''):
    found = element.find(tag)
    return found.text if found is not None and found.text else default

def get_interface_cidr(opnsense_root, interface_name):
    """
    Finds an interface by its logical name (e.g., 'lan', 'opt2') in the <interfaces>
    section and calculates its network address in CIDR notation.
    """
    interfaces_elem = opnsense_root.find('interfaces')
    if interfaces_elem is None:
        return None

    interface_elem = interfaces_elem.find(interface_name)
    if interface_elem is None:
        return None

    ipaddr = get_text_from_element(interface_elem, 'ipaddr')
    subnet = get_text_from_element(interface_elem, 'subnet')

    if ipaddr and subnet:
        try:
            # Calculate the network address from the host IP and subnet mask
            network = ipaddress.ip_network(f'{ipaddr}/{subnet}', strict=False)
            return str(network)
        except ValueError:
            return None
    return None

def map_dh_group_to_modp(dhgroup):
    dh_map = {
        '2': 'modp1024',
        '5': 'modp1536',
        '14': 'modp2048',
        '15': 'modp3072',
        '16': 'modp4096',
        '17': 'modp6144',
        '18': 'modp8192',
        '19': 'ecp256',
        '20': 'ecp384',
        '21': 'ecp521',
        '26': 'ecp224',
        '27': 'ecp224bp',
        '28': 'ecp256bp',
        '29': 'ecp384bp',
        '30': 'ecp512bp',
        '31': 'x25519',
        '32': 'x448',
    }
    return dh_map.get(dhgroup, f'modp_unknown_{dhgroup}')

def clean_hash_name(hash_name):
    return hash_name.replace('hmac_', '')

def get_or_create_sub_element(parent, tag_name, attrib={}):
    child = parent.find(tag_name)
    if child is None:
        child = ET.SubElement(parent, tag_name, attrib)
    return child

# --- Main Conversion Logic ---
def main():
    """
    Reads the full OPNsense config as text, performs a conversion of the
    <ipsec> block in memory, generates a new <Swanctl> block as a string,
    and then surgically replaces or inserts this block into the original
    text content to preserve all original formatting.
    """
    print(f"Reading full configuration from '{INPUT_CONFIG_PATH}'...")

    try:
        if not os.path.exists(INPUT_CONFIG_PATH):
            print(f"WARNING: '{INPUT_CONFIG_PATH}' not found. Creating a sample file for the test run.")
            with open(INPUT_CONFIG_PATH, 'w', encoding='utf-8') as f:
                f.write("""<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>firewall</hostname>
    <other><value/></other>
  </system>
  <interfaces>
    <wan>
      <if>ix0</if>
      <descr>WAN</descr>
      <enable>1</enable>
      <ipaddr>1.2.3.4</ipaddr>
      <subnet>30</subnet>
    </wan>
    <lan>
      <if>ix1</if>
      <descr>LAN</descr>
      <enable>1</enable>
      <ipaddr>10.10.10.1</ipaddr>
      <subnet>24</subnet>
    </lan>
    <opt2>
      <if>ix0_vlan123</if>
      <descr>VLAN123</descr>
      <enable>1</enable>
      <ipaddr>192.168.123.1</ipaddr>
      <subnet>24</subnet>
    </opt2>
  </interfaces>
  <ipsec>
    <phase1>
      <ikeid>3</ikeid>
      <iketype>ikev1</iketype><interface>wan</interface><mode>main</mode>
      <myid_type>address</myid_type><myid_data>1.2.3.4</myid_data>
      <peerid_type>address</peerid_type><peerid_data>5.6.7.8</peerid_data>
      <encryption-algorithm><name>aes</name><keylen>256</keylen></encryption-algorithm>
      <lifetime>28800</lifetime><pre-shared-key>aVerySecretKey</pre-shared-key>
      <authentication_method>pre_shared_key</authentication_method>
      <descr>ipsec test</descr><nat_traversal>on</nat_traversal><dhgroup>16</dhgroup>
      <hash-algorithm>sha256</hash-algorithm><remote-gateway>5.6.7.8</remote-gateway>
      <dpd_delay>10</dpd_delay><dpd_maxfail>5</dpd_maxfail>
    </phase1>
    <phase2>
      <ikeid>3</ikeid><uniqid>5d541916220aa</uniqid><mode>tunnel</mode>
      <pfsgroup>16</pfsgroup><lifetime>3600</lifetime><descr>tunnel 1</descr>
      <protocol>esp</protocol>
      <localid><type>opt2</type></localid>
      <remoteid><type>network</type><address>10.22.0.0</address><netbits>24</netbits></remoteid>
      <encryption-algorithm-option><name>aes256</name></encryption-algorithm-option>
      <hash-algorithm-option>hmac_sha256</hash-algorithm-option>
      <reqid>1</reqid>
    </phase2>
  </ipsec>
  <Swanctl version="1.0.0">
    <Connections/>
    <locals/>
    <remotes/>
    <children/>
    <Pools/>
    <VTIs/>
    <SPDs/>
  </Swanctl>
</opnsense>
""")
        with open(INPUT_CONFIG_PATH, 'r', encoding='utf-8') as f:
            original_xml_content = f.read()

        opnsense_root = ET.fromstring(original_xml_content)

    except FileNotFoundError:
        print(f"ERROR: The input file '{INPUT_CONFIG_PATH}' was not found.")
        return
    except ET.ParseError as e:
        print(f"ERROR: The XML file '{INPUT_CONFIG_PATH}' could not be parsed: {e}")
        return

    old_ipsec = opnsense_root.find('ipsec')
    if old_ipsec is None:
        print("No <ipsec> section found to convert. Nothing to do.")
        with open(OUTPUT_CONFIG_PATH, 'w', encoding='utf-8') as f:
            f.write(original_xml_content)
        return

    # Create root for the new pre-shared keys. This is temporary for building the new keys.
    pre_shared_keys_elem = ET.Element('preSharedKeys')

    swanctl_root = get_or_create_sub_element(opnsense_root, 'Swanctl', {"version": "1.0.0"})
    connections_elem = get_or_create_sub_element(swanctl_root, 'Connections')
    children_elem = get_or_create_sub_element(swanctl_root, 'children')
    spds_elem = get_or_create_sub_element(swanctl_root, 'SPDs')
    locals_elem = get_or_create_sub_element(swanctl_root, "locals")
    remotes_elem = get_or_create_sub_element(swanctl_root, "remotes")
    get_or_create_sub_element(swanctl_root, "Pools")
    get_or_create_sub_element(swanctl_root, "VTIs")


    ikeid_to_uuid_map = {}
    print("Starting conversion of Phase 1 to <Connection>...")

    for p1 in old_ipsec.findall('phase1'):
        p1_ikeid = get_text_from_element(p1, 'ikeid')
        if not p1_ikeid: continue

        conn_uuid = str(uuid.uuid4())
        ikeid_to_uuid_map[p1_ikeid] = conn_uuid

        conn = ET.SubElement(connections_elem, "Connection", {"uuid": conn_uuid})

        ET.SubElement(conn, "enabled").text = '0' if p1.find('disabled') is not None else '1'

        # Assembling the proposals
        enc_algo = get_text_from_element(p1, 'encryption-algorithm/name')
        enc_keylen = get_text_from_element(p1, 'encryption-algorithm/keylen')
        hash_algo = get_text_from_element(p1, 'hash-algorithm')
        dh_group = get_text_from_element(p1, 'dhgroup')
        p1_proposals = f"{enc_algo}{enc_keylen}-{hash_algo}-{map_dh_group_to_modp(dh_group)}"
        ET.SubElement(conn, "proposals").text = p1_proposals

        ET.SubElement(conn, "unique").text = "no"
        ET.SubElement(conn, "aggressive").text = '1' if get_text_from_element(p1, 'mode') == 'aggressive' else '0'
        ET.SubElement(conn, "version").text = '2' if get_text_from_element(p1, 'iketype') == 'ikev2' else '1'
        ET.SubElement(conn, "mobike").text = "1"
        ET.SubElement(conn, "local_addrs").text = get_text_from_element(p1, 'myid_data')
        ET.SubElement(conn, "local_port")
        ET.SubElement(conn, "remote_addrs").text = get_text_from_element(p1, 'remote-gateway')
        ET.SubElement(conn, "remote_port")
        ET.SubElement(conn, "encap").text = '1' if get_text_from_element(p1, 'nat_traversal') == 'on' else '0'
        ET.SubElement(conn, "reauth_time")
        ET.SubElement(conn, "rekey_time").text = get_text_from_element(p1, 'lifetime')
        ET.SubElement(conn, "over_time")
        ET.SubElement(conn, "dpd_delay").text = get_text_from_element(p1, 'dpd_delay')
        ET.SubElement(conn, "dpd_timeout")
        ET.SubElement(conn, "pools")
        ET.SubElement(conn, "send_certreq").text = "1"
        ET.SubElement(conn, "send_cert")
        ET.SubElement(conn, "keyingtries")
        ET.SubElement(conn, "description").text = get_text_from_element(p1, 'descr')

        # Handle PSK migration for both IPsec and Swanctl sections.
        auth_method = get_text_from_element(p1, 'authentication_method')
        if auth_method == 'pre_shared_key':
            psk = get_text_from_element(p1, 'pre-shared-key')
            myid_type = get_text_from_element(p1, 'myid_type')
            peerid_type = get_text_from_element(p1, 'peerid_type')
            myid_data = get_text_from_element(p1, 'myid_data')
            peerid_data = get_text_from_element(p1, 'peerid_data')
            remote_gateway = get_text_from_element(p1, 'remote-gateway')

            # Create the PreSharedKey entry for later insertion into the <IPsec> section.
            if psk:
                psk_uuid = str(uuid.uuid4())
                psk_elem = ET.SubElement(pre_shared_keys_elem, "preSharedKey", {"uuid": psk_uuid})
                ET.SubElement(psk_elem, "ident").text = myid_data
                ET.SubElement(psk_elem, "remote_ident").text = remote_gateway
                ET.SubElement(psk_elem, "keyType").text = "PSK"
                ET.SubElement(psk_elem, "Key").text = psk
                ET.SubElement(psk_elem, "description")

            # Create <local> and <remote> entries if using address identifiers.
            # Check for supported identifier types for PSK. Supports 'address' for both,
            # or 'peeraddress' for the peer, where the gateway IP is used as the identifier.
            if myid_type == 'address' and peerid_type in ('address', 'peeraddress'):
                # Determine the correct peer identifier.
                # If peerid_type is 'peeraddress', use the remote-gateway IP.
                # Otherwise, use the explicitly defined peerid_data.
                actual_peerid_data = remote_gateway if peerid_type == 'peeraddress' else peerid_data

                local_uuid = str(uuid.uuid4())
                local_elem = ET.SubElement(locals_elem, "local", {"uuid": local_uuid})
                ET.SubElement(local_elem, "enabled").text = '1'
                ET.SubElement(local_elem, "connection").text = conn_uuid
                ET.SubElement(local_elem, "round").text = '0'
                ET.SubElement(local_elem, "auth").text = 'psk'
                ET.SubElement(local_elem, "id").text = myid_data
                ET.SubElement(local_elem, "eap_id")
                ET.SubElement(local_elem, "certs")
                ET.SubElement(local_elem, "pubkeys")
                ET.SubElement(local_elem, "description")

                remote_uuid = str(uuid.uuid4())
                remote_elem = ET.SubElement(remotes_elem, "remote", {"uuid": remote_uuid})
                ET.SubElement(remote_elem, "enabled").text = '1'
                ET.SubElement(remote_elem, "connection").text = conn_uuid
                ET.SubElement(remote_elem, "round").text = '0'
                ET.SubElement(remote_elem, "auth").text = 'psk'
                ET.SubElement(remote_elem, "id").text = actual_peerid_data
                ET.SubElement(remote_elem, "eap_id")
                ET.SubElement(remote_elem, "groups")
                ET.SubElement(remote_elem, "certs")
                ET.SubElement(remote_elem, "cacerts")
                ET.SubElement(remote_elem, "pubkeys")
                ET.SubElement(remote_elem, "description")
            else:
                 print(f"  - WARNING: Phase 1 with ikeid {p1_ikeid} uses PSK, but identifier types ('{myid_type}', '{peerid_type}') are not a supported combination ('address'/'address' or 'address'/'peeraddress').")

        print(f"  - Phase 1 (ikeid: {p1_ikeid}) -> Connection (uuid: {conn_uuid}) converted.")

    print("\nStarting conversion of Phase 2 to <child>...")
    for p2 in old_ipsec.findall('phase2'):
        p2_ikeid = get_text_from_element(p2, 'ikeid')
        p2_uniqid = get_text_from_element(p2, 'uniqid')
        if p2_ikeid not in ikeid_to_uuid_map:
            print(f"  - WARNING: Phase 2 with ikeid={p2_ikeid} (uniqid: {p2_uniqid}) has no matching Phase 1. Skipping.")
            continue

        child_uuid = str(uuid.uuid4())
        parent_conn_uuid = ikeid_to_uuid_map[p2_ikeid]

        child = ET.SubElement(children_elem, "child", {"uuid": child_uuid})

        # Mapping the tags
        ET.SubElement(child, "enabled").text = '0' if p2.find('disabled') is not None else '1'
        ET.SubElement(child, "connection").text = parent_conn_uuid
        ET.SubElement(child, "reqid").text = get_text_from_element(p2, 'reqid')
        
        # Assembling the ESP proposals
        p2_enc_algos = []
        for opt in p2.findall('encryption-algorithm-option'):
            name = get_text_from_element(opt, 'name')
            keylen = get_text_from_element(opt, 'keylen')
            if name:
               p2_enc_algos.append(f"{name}{keylen}")

        p2_hash_algos = [clean_hash_name(opt.text) for opt in p2.findall('hash-algorithm-option') if opt.text]
        p2_pfs_group = map_dh_group_to_modp(get_text_from_element(p2, 'pfsgroup'))

        # Create all combinations (Cartesian product) if multiple algorithms are defined
        esp_proposals = []
        if p2_enc_algos and p2_hash_algos:
            for combo in product(p2_enc_algos, p2_hash_algos):
                esp_proposals.append(f"{combo[0]}-{combo[1]}-{p2_pfs_group}")
        ET.SubElement(child, "esp_proposals").text = ",".join(esp_proposals)
        
        ET.SubElement(child, "sha256_96").text = "0"
        ET.SubElement(child, "start_action").text = "start"
        ET.SubElement(child, "close_action").text = "none"
        ET.SubElement(child, "dpd_action").text = "clear"
        ET.SubElement(child, "mode").text = get_text_from_element(p2, 'mode')
        ET.SubElement(child, "policies").text = "1"

        # Handle local traffic selector, resolving interface names to networks
        localid_elem = p2.find('localid')
        local_ts_text = ""
        if localid_elem is not None:
            id_type = get_text_from_element(localid_elem, 'type')
            if id_type == 'network':
                addr = get_text_from_element(localid_elem, 'address')
                netbits = get_text_from_element(localid_elem, 'netbits')
                if addr and netbits:
                    local_ts_text = f"{addr}/{netbits}"
            elif id_type: # Type is an interface name
                cidr = get_interface_cidr(opnsense_root, id_type)
                if cidr:
                    local_ts_text = cidr
                else:
                    print(f"  - WARNING: Could not resolve interface '{id_type}' to a network for P2 uniqid {p2_uniqid}.")
        ET.SubElement(child, "local_ts").text = local_ts_text

        # Handle remote traffic selector, resolving interface names to networks
        remoteid_elem = p2.find('remoteid')
        remote_ts_text = ""
        if remoteid_elem is not None:
            id_type = get_text_from_element(remoteid_elem, 'type')
            if id_type == 'network':
                addr = get_text_from_element(remoteid_elem, 'address')
                netbits = get_text_from_element(remoteid_elem, 'netbits')
                if addr and netbits:
                    remote_ts_text = f"{addr}/{netbits}"
            elif id_type: # Type is an interface name
                cidr = get_interface_cidr(opnsense_root, id_type)
                if cidr:
                    remote_ts_text = cidr
                else:
                    print(f"  - WARNING: Could not resolve interface '{id_type}' to a network for P2 uniqid {p2_uniqid}.")
        ET.SubElement(child, "remote_ts").text = remote_ts_text
        
        ET.SubElement(child, "rekey_time").text = get_text_from_element(p2, 'lifetime')
        ET.SubElement(child, "description").text = get_text_from_element(p2, 'descr')
        
        # Process SPD entry (if present)
        spd_source = get_text_from_element(p2, 'spd')
        if spd_source:
            spd_uuid = str(uuid.uuid4())
            spd = ET.SubElement(spds_elem, "SPD", {"uuid": spd_uuid})
            ET.SubElement(spd, "enabled").text = '1'
            ET.SubElement(spd, "protocol").text = get_text_from_element(p2, 'protocol', 'esp')
            ET.SubElement(spd, "connection_child").text = child_uuid
            ET.SubElement(spd, "source").text = spd_source
            ET.SubElement(spd, "destination")
            ET.SubElement(spd, "description")

        print(f"  - Phase 2 (ikeid: {p2_ikeid}, uniqid: {p2_uniqid}) -> child (uuid: {child_uuid}) converted.")

    print("\nConversion complete.")

    final_content = original_xml_content

    # First, handle the <preSharedKeys> block update via targeted regex replacement.
    if list(pre_shared_keys_elem):  # Check if any keys were actually added
        print("Found pre-shared keys to migrate. Updating <preSharedKeys> block.")
        ET.indent(pre_shared_keys_elem, space="  ", level=2) # Indent relative to <IPsec> parent
        new_psk_block_str = ET.tostring(pre_shared_keys_elem, encoding='unicode', short_empty_elements=True)

        psk_pattern = re.compile(r"<preSharedKeys\b[^>]*>(?:(?!</preSharedKeys>)[\s\S])*</preSharedKeys>|<preSharedKeys\s*/>")

        # Use a lambda function for replacement to preserve indentation of the block itself.
        def replace_psk(match):
            original_block = match.group(0)
            line_start_pos = final_content.rfind('\n', 0, match.start()) + 1
            indentation = final_content[line_start_pos:match.start()]

            new_block_lines = new_psk_block_str.splitlines()
            if new_block_lines:
                first_line = new_block_lines[0]
                indented_subsequent_lines = [f"{indentation}{line}" for line in new_block_lines[1:]]
                return "\n".join([first_line] + indented_subsequent_lines)
            return ""

        if psk_pattern.search(final_content):
            final_content = psk_pattern.sub(replace_psk, final_content, count=1)
            print("  - Successfully replaced existing <preSharedKeys> block.")
        else:
            print("  - WARNING: Could not find a <preSharedKeys> block or tag in <IPsec> to replace.")

    # Second, handle the <Swanctl> block, operating on the already modified content.
    final_swanctl_element = opnsense_root.find('Swanctl')
    if final_swanctl_element is not None:
        # Format the new Swanctl element internally using the reliable ET.indent function.
        ET.indent(final_swanctl_element, space="  ", level=0)
        # Convert the formatted element to a clean string, using self-closing tags for empty elements.
        new_swanctl_block_str = ET.tostring(final_swanctl_element, encoding='unicode', short_empty_elements=True)

        current_content_for_swanctl = final_content
        swanctl_pattern = re.compile(r"<Swanctl.*?>.*?</Swanctl>", re.DOTALL)
        match = swanctl_pattern.search(current_content_for_swanctl)

        if match:
            print("Found existing <Swanctl> block. Replacing it.")
            block_start, block_end = match.start(), match.end()
            line_start_pos = current_content_for_swanctl.rfind('\n', 0, block_start) + 1
            indentation = current_content_for_swanctl[line_start_pos:block_start]
            
            new_block_lines = new_swanctl_block_str.splitlines()
            if new_block_lines:
                # The first line is positioned by the original slice, so it doesn't need indentation.
                first_line = new_block_lines[0]
                # All subsequent lines must be prefixed with the original block's indentation.
                indented_subsequent_lines = [f"{indentation}{line}" for line in new_block_lines[1:]]
                # Rebuild the final block string.
                final_new_block = "\n".join([first_line] + indented_subsequent_lines)
            else:
                final_new_block = ""

            final_content = current_content_for_swanctl[:block_start] + final_new_block + current_content_for_swanctl[block_end:]
            
        else:
            print("No existing <Swanctl> block found. Inserting new block after <ipsec>.")
            ipsec_pattern = re.compile(r"</ipsec>", re.DOTALL)
            ipsec_match = ipsec_pattern.search(current_content_for_swanctl)
            if ipsec_match:
                insertion_point = ipsec_match.end()
                line_start_pos = current_content_for_swanctl.rfind('\n', 0, ipsec_match.start()) + 1
                indentation = current_content_for_swanctl[line_start_pos:ipsec_match.start()]

                # Prepend indentation to ALL lines as we are on a new line.
                indented_new_block = "".join([f"{indentation}{line}\n" for line in new_swanctl_block_str.splitlines()]).rstrip()
                
                final_content = current_content_for_swanctl[:insertion_point] + '\n' + indented_new_block + current_content_for_swanctl[insertion_point:]
            else:
                 print("  - Fallback: Could not find </ipsec>, inserting before </opnsense>.")
                 insertion_point_fallback = current_content_for_swanctl.rfind('</opnsense>')
                 indentation = "  "
                 indented_fallback_block = "".join([f"{indentation}{line}\n" for line in new_swanctl_block_str.splitlines()]).rstrip()

                 final_content = (
                    current_content_for_swanctl[:insertion_point_fallback]
                     + indented_fallback_block + "\n"
                     + current_content_for_swanctl[insertion_point_fallback:]
                 )

        print(f"Saving format-preserved configuration to '{OUTPUT_CONFIG_PATH}'...")
        with open(OUTPUT_CONFIG_PATH, 'w', encoding='utf-8') as f:
            f.write(final_content)
        print("Save successful.")
    else:
        print("ERROR: Could not find or generate the <Swanctl> block.")

if __name__ == '__main__':
    main()
