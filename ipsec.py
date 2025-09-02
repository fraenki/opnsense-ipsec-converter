#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import uuid
from itertools import product
import os
import re

# --- Configuration ---
# Path to the original OPNsense configuration file
INPUT_CONFIG_PATH = 'config.old.xml'

# Path for the newly generated configuration file
OUTPUT_CONFIG_PATH = 'config.new.xml'

# --- Helper Functions ---
def get_text_from_element(element, tag, default=''):
    found = element.find(tag)
    return found.text if found is not None and found.text else default

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
      <localid><type>network</type><address>10.11.0.0</address><netbits>24</netbits></localid>
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

    swanctl_root = get_or_create_sub_element(opnsense_root, 'Swanctl', {"version": "1.0.0"})
    connections_elem = get_or_create_sub_element(swanctl_root, 'Connections')
    children_elem = get_or_create_sub_element(swanctl_root, 'children')
    spds_elem = get_or_create_sub_element(swanctl_root, 'SPDs')
    get_or_create_sub_element(swanctl_root, "locals")
    get_or_create_sub_element(swanctl_root, "remotes")
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
        p2_enc_algos = [get_text_from_element(opt, 'name') for opt in p2.findall('encryption-algorithm-option') if get_text_from_element(opt, 'name')]
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

        # convert local/remote subnets to CIDR
        local_addr = get_text_from_element(p2, 'localid/address')
        local_bits = get_text_from_element(p2, 'localid/netbits')
        ET.SubElement(child, "local_ts").text = f"{local_addr}/{local_bits}" if local_addr and local_bits else ""

        remote_addr = get_text_from_element(p2, 'remoteid/address')
        remote_bits = get_text_from_element(p2, 'remoteid/netbits')
        ET.SubElement(child, "remote_ts").text = f"{remote_addr}/{remote_bits}" if remote_addr and remote_bits else ""
        
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
            ET.SubElement(spd, "description").text = f"SPD for child {child_uuid}"
            print(f"    - SPD entry created for Child {child_uuid}.")

        print(f"  - Phase 2 (ikeid: {p2_ikeid}, uniqid: {p2_uniqid}) -> child (uuid: {child_uuid}) converted.")

    print("\nConversion complete.")

    final_swanctl_element = opnsense_root.find('Swanctl')
    if final_swanctl_element is not None:
        
        # Format the new Swanctl element internally using the reliable ET.indent function.
        ET.indent(final_swanctl_element, space="  ", level=0)
        
        # Convert the formatted element to a clean string, using self-closing tags for empty elements.
        new_swanctl_block_str = ET.tostring(final_swanctl_element, encoding='unicode', short_empty_elements=True)

        final_content = ""
        swanctl_pattern = re.compile(r"<Swanctl.*?>.*?</Swanctl>", re.DOTALL)
        match = swanctl_pattern.search(original_xml_content)

        if match:
            print("Found existing <Swanctl> block. Replacing it.")
            block_start, block_end = match.start(), match.end()
            line_start_pos = original_xml_content.rfind('\n', 0, block_start) + 1
            indentation = original_xml_content[line_start_pos:block_start]
            
            new_block_lines = new_swanctl_block_str.splitlines()
            if new_block_lines:
                # The first line is positioned by the original slice, so it doesn't need indentation.
                first_line = new_block_lines[0]
                # All subsequent lines must be prefixed with the original block's indentation.
                indented_subsequent_lines = [f"{indentation}{line}" for line in new_block_lines[1:]]
                # Rebuild the final block string.
                final_new_block = "\n".join([first_line] + indented_subsequent_lines)
            else:
                final_new_block = "" # Handle unlikely case of an empty block

            # Reconstruct the entire file by replacing the old block with the perfectly formatted new one.
            final_content = original_xml_content[:block_start] + final_new_block + original_xml_content[block_end:]
            
        else:
            print("No existing <Swanctl> block found. Inserting new block after <ipsec>.")
            ipsec_pattern = re.compile(r"</ipsec>", re.DOTALL)
            ipsec_match = ipsec_pattern.search(original_xml_content)
            if ipsec_match:
                insertion_point = ipsec_match.end()
                line_start_pos = original_xml_content.rfind('\n', 0, ipsec_match.start()) + 1
                indentation = original_xml_content[line_start_pos:ipsec_match.start()]
                
                # This logic is correct: prepend indentation to ALL lines as we are on a new line.
                indented_new_block = "".join([f"{indentation}{line}\n" for line in new_swanctl_block_str.splitlines()]).rstrip()
                
                final_content = original_xml_content[:insertion_point] + '\n' + indented_new_block + original_xml_content[insertion_point:]
            else:
                 print("  - Fallback: Could not find </ipsec>, inserting before </opnsense>.")
                 insertion_point_fallback = original_xml_content.rfind('</opnsense>')
                 indentation = "  "
                 indented_fallback_block = "".join([f"{indentation}{line}\n" for line in new_swanctl_block_str.splitlines()]).rstrip()

                 final_content = (
                    original_xml_content[:insertion_point_fallback]
                     + indented_fallback_block + "\n"
                     + original_xml_content[insertion_point_fallback:]
                 )

        print(f"Saving format-preserved configuration to '{OUTPUT_CONFIG_PATH}'...")
        with open(OUTPUT_CONFIG_PATH, 'w', encoding='utf-8') as f:
            f.write(final_content)
        print("Save successful.")
    else:
        print("ERROR: Could not generate the <Swanctl> block.")

if __name__ == '__main__':
    main()
