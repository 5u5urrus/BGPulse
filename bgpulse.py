#!/usr/bin/env python3
"""
Enhanced BGP Security Assessment Tool

BGPulse is a comprehensive, automated BGP security testing tool that runs with a single command:
python bgp.py <ip> <port>

This crazy script performs a series of tests to identify potential BGP security vulnerabilities:
1. Basic connectivity testing
2. Protocol compliance checks
3. Authentication probing
4. Capability negotiation testing
5. ASN validation
6. Malformed message handling
7. Route filtering assessment
8. Session behavior analysis
9. Resource exhaustion resilience

Author: Vahe Demirkhanyan
License: MIT
"""
import socket
import sys
import struct
import time
import ipaddress
import random
import binascii
import threading
import argparse
from collections import namedtuple

DEFAULT_PORT = 179
DEFAULT_TIMEOUT = 5
MAX_RESPONSE_SIZE = 8192

BGP_OPEN = 1
BGP_UPDATE = 2
BGP_NOTIFICATION = 3
BGP_KEEPALIVE = 4
BGP_ROUTE_REFRESH = 5

CAP_MULTIPROTOCOL = 1
CAP_ROUTE_REFRESH = 2
CAP_OUTBOUND_ROUTE_FILTERING = 3
CAP_EXTENDED_NEXTHOP = 5
CAP_EXTENDED_MESSAGE = 6
CAP_GRACEFUL_RESTART = 64
CAP_4_OCTET_ASN = 65
CAP_ADD_PATHS = 69
CAP_ENHANCED_ROUTE_REFRESH = 70

ERR_MESSAGE_HEADER = 1
ERR_OPEN_MESSAGE = 2
ERR_UPDATE_MESSAGE = 3
ERR_HOLD_TIMER_EXPIRED = 4
ERR_FSM_ERROR = 5
ERR_CEASE = 6

OPEN_ERR_UNSUPPORTED_VERSION = 1
OPEN_ERR_BAD_PEER_AS = 2
OPEN_ERR_BAD_BGP_IDENTIFIER = 3
OPEN_ERR_UNSUPPORTED_OPTIONAL_PARAM = 4
OPEN_ERR_AUTHENTICATION_FAILURE = 5
OPEN_ERR_UNACCEPTABLE_HOLD_TIME = 6
OPEN_ERR_UNSUPPORTED_CAPABILITY = 7

TestResult = namedtuple('TestResult', ['name', 'result', 'details', 'severity'])

class BGPSecurityTester:
    def __init__(self, target_ip, target_port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT, verbose=True):
        self.target_ip = target_ip
        self.target_port = target_port
        self.timeout = timeout
        self.verbose = verbose
        self.results = []
        self.open_parameters = {
            'version': 4,
            'my_as': 64512,
            'hold_time': 180,
            'bgp_identifier': '1.1.1.1',
            'capabilities': []
        }
        self.peer_open_params = None
        self.session_established = False
        
    def log(self, message, level="INFO"):
        if self.verbose:
            print(f"[{level}] {message}")
            
    def add_result(self, name, result, details="", severity="INFO"):
        self.results.append(TestResult(name, result, details, severity))
        
    def run_all_tests(self):
        self.log(f"Starting comprehensive BGP security assessment against {self.target_ip}:{self.target_port}")
        
        try:
            if not self.test_connectivity():
                self.log("Basic connectivity test failed. Aborting further tests.", "ERROR")
                return self.results
                
            self.test_session_establishment()
            self.test_asn_handling()
            self.test_capability_handling()
            self.test_malformed_messages()
            self.test_route_filtering()
            self.test_session_behavior()
            self.test_resource_limits()
            
            self.print_results_summary()
            
        except KeyboardInterrupt:
            self.log("Assessment interrupted by user.", "WARN")
        except Exception as e:
            self.log(f"Unexpected error during assessment: {str(e)}", "ERROR")
        
        return self.results

    def test_connectivity(self):
        self.log(f"Testing basic TCP connectivity to {self.target_ip}:{self.target_port}...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, self.target_port))
            sock.close()
            
            self.add_result("Basic Connectivity", "PASS", 
                           f"Successfully established TCP connection to {self.target_ip}:{self.target_port}")
            return True
            
        except socket.error as e:
            self.add_result("Basic Connectivity", "FAIL", 
                           f"Failed to connect: {str(e)}", "HIGH")
            return False

    def build_bgp_open(self, **kwargs):
        params = dict(self.open_parameters)
        params.update(kwargs)
        
        try:
            bgp_id_bytes = socket.inet_aton(params['bgp_identifier'])
        except socket.error:
            bgp_id_bytes = b"\x01\x01\x01\x01"
            
        marker = b"\xff" * 16
        
        opt_params = b""
        if params.get('capabilities'):
            for cap_code, cap_value in params['capabilities']:
                cap_param = struct.pack('>BB', cap_code, len(cap_value)) + cap_value
                opt_params += struct.pack('>BB', 2, len(cap_param)) + cap_param
                
        opt_param_len = len(opt_params)
        
        if params['my_as'] > 65535:
            as_bytes = struct.pack('>H', 23456)
            has_4byte = any(cap[0] == CAP_4_OCTET_ASN for cap in params.get('capabilities', []))
            if not has_4byte:
                cap_value = struct.pack('>I', params['my_as'])
                cap_param = struct.pack('>BB', CAP_4_OCTET_ASN, len(cap_value)) + cap_value
                opt_params += struct.pack('>BB', 2, len(cap_param)) + cap_param
                opt_param_len = len(opt_params)
        else:
            as_bytes = struct.pack('>H', params['my_as'])
        
        open_payload = (
            struct.pack('>B', params['version']) + 
            as_bytes + 
            struct.pack('>H', params['hold_time']) + 
            bgp_id_bytes + 
            struct.pack('>B', opt_param_len) + 
            opt_params
        )
        
        total_length = 19 + len(open_payload)
        
        open_msg = (
            marker +
            struct.pack('>H', total_length) +
            struct.pack('>B', BGP_OPEN) +
            open_payload
        )
        
        return open_msg

    def build_bgp_update(self, withdrawn_routes=None, path_attributes=None, nlri=None):
        marker = b"\xff" * 16
        
        withdrawn_bytes = b""
        if withdrawn_routes:
            for prefix, length in withdrawn_routes:
                prefix_bytes = socket.inet_aton(prefix)
                prefix_bytes_needed = (length + 7) // 8
                withdrawn_bytes += struct.pack('>B', length) + prefix_bytes[:prefix_bytes_needed]
                
        withdrawn_length = len(withdrawn_bytes)
        withdrawn_length_bytes = struct.pack('>H', withdrawn_length)
        
        path_attr_bytes = b""
        if path_attributes:
            for attr in path_attributes:
                path_attr_bytes += attr
                
        path_attr_length = len(path_attr_bytes)
        path_attr_length_bytes = struct.pack('>H', path_attr_length)
        
        nlri_bytes = b""
        if nlri:
            for prefix, length in nlri:
                prefix_bytes = socket.inet_aton(prefix)
                prefix_bytes_needed = (length + 7) // 8
                nlri_bytes += struct.pack('>B', length) + prefix_bytes[:prefix_bytes_needed]
        
        update_payload = (
            withdrawn_length_bytes +
            withdrawn_bytes +
            path_attr_length_bytes +
            path_attr_bytes +
            nlri_bytes
        )
        
        total_length = 19 + len(update_payload)
        
        update_msg = (
            marker +
            struct.pack('>H', total_length) +
            struct.pack('>B', BGP_UPDATE) +
            update_payload
        )
        
        return update_msg

    def build_bgp_keepalive(self):
        marker = b"\xff" * 16
        length = 19
        return marker + struct.pack('>H', length) + struct.pack('>B', BGP_KEEPALIVE)

    def build_malformed_message(self, malformation_type):
        if malformation_type == "marker":
            marker = b"\xff" * 15 + b"\x00"
            return marker + struct.pack('>H', 19) + struct.pack('>B', BGP_KEEPALIVE)
            
        elif malformation_type == "length":
            marker = b"\xff" * 16
            return marker + struct.pack('>H', 10) + struct.pack('>B', BGP_KEEPALIVE)
            
        elif malformation_type == "type":
            marker = b"\xff" * 16
            return marker + struct.pack('>H', 19) + struct.pack('>B', 6)
            
        elif malformation_type == "open_version":
            open_msg = self.build_bgp_open(version=99)
            return open_msg
            
        elif malformation_type == "truncated":
            open_msg = self.build_bgp_open()
            return open_msg[:25]
            
        else:
            return self.build_bgp_keepalive()

    def parse_bgp_messages(self, data):
        messages = []
        offset = 0

        while offset < len(data):
            if len(data) - offset < 19:
                break

            marker = data[offset:offset+16]
            if marker != b"\xff" * 16:
                self.log(f"Invalid BGP marker at offset {offset}: {binascii.hexlify(marker)}", "WARN")
                break
            offset += 16

            try:
                length_bytes = data[offset:offset+2]
                msg_length = struct.unpack('>H', length_bytes)[0]
                offset += 2

                if msg_length < 19 or msg_length > len(data) - offset + 3:
                    self.log(f"Invalid BGP length {msg_length} at offset {offset-2}", "WARN")
                    break

                msg_type = data[offset]
                offset += 1

                payload_length = msg_length - 19
                payload = data[offset:offset+payload_length]
                offset += payload_length

                msg_info = {
                    'type': msg_type,
                    'type_name': self.bgp_type_to_string(msg_type),
                    'length': msg_length,
                    'raw_payload': payload
                }

                if msg_type == BGP_OPEN and len(payload) >= 9:
                    msg_info.update(self.parse_open_message(payload))
                elif msg_type == BGP_UPDATE:
                    msg_info.update(self.parse_update_message(payload))
                elif msg_type == BGP_NOTIFICATION and len(payload) >= 2:
                    msg_info.update(self.parse_notification_message(payload))

                messages.append(msg_info)

            except Exception as e:
                self.log(f"Error parsing BGP message: {str(e)}", "ERROR")
                break

        return messages

    def parse_open_message(self, payload):
        if len(payload) < 9:
            return {'error': 'OPEN message too short'}
        
        version = payload[0]
        my_as = struct.unpack('>H', payload[1:3])[0]
        hold_time = struct.unpack('>H', payload[3:5])[0]
        bgp_id = socket.inet_ntoa(payload[5:9])
        opt_param_len = payload[9]
        
        result = {
            'version': version,
            'as': my_as,
            'hold_time': hold_time,
            'bgp_id': bgp_id,
            'opt_param_len': opt_param_len,
            'capabilities': []
        }
        
        if opt_param_len > 0 and len(payload) >= 10 + opt_param_len:
            params_data = payload[10:10+opt_param_len]
            offset = 0
            
            while offset < len(params_data):
                param_type = params_data[offset]
                param_len = params_data[offset+1]
                param_value = params_data[offset+2:offset+2+param_len]
                
                if param_type == 2:
                    cap_offset = 0
                    while cap_offset < len(param_value):
                        cap_code = param_value[cap_offset]
                        cap_len = param_value[cap_offset+1]
                        cap_data = param_value[cap_offset+2:cap_offset+2+cap_len]
                        
                        cap_info = {'code': cap_code, 'data': cap_data}
                        
                        if cap_code == CAP_4_OCTET_ASN and cap_len == 4:
                            cap_info['4_octet_asn'] = struct.unpack('>I', cap_data)[0]
                            result['real_as'] = cap_info['4_octet_asn']
                        elif cap_code == CAP_MULTIPROTOCOL and cap_len == 4:
                            afi, safi = struct.unpack('>HBB', cap_data)
                            cap_info['afi'] = afi
                            cap_info['safi'] = safi
                            
                        result['capabilities'].append(cap_info)
                        cap_offset += 2 + cap_len
                
                offset += 2 + param_len
        
        return result

    def parse_update_message(self, payload):
        if len(payload) < 4:
            return {'error': 'UPDATE message too short'}
            
        offset = 0
        
        withdrawn_len = struct.unpack('>H', payload[offset:offset+2])[0]
        offset += 2
        
        withdrawn_routes = []
        withdrawn_end = offset + withdrawn_len
        if withdrawn_len > 0:
            withdrawn_data = payload[offset:withdrawn_end]
            pass
            
        offset = withdrawn_end
        
        if offset + 2 > len(payload):
            return {'error': 'UPDATE message truncated at path attributes length'}
            
        path_attr_len = struct.unpack('>H', payload[offset:offset+2])[0]
        offset += 2
        
        path_attributes = []
        path_attr_end = offset + path_attr_len
        
        if path_attr_len > 0:
            path_attr_data = payload[offset:path_attr_end]
            attr_offset = 0
            while attr_offset < len(path_attr_data):
                if attr_offset + 2 > len(path_attr_data):
                    break
                    
                flags = path_attr_data[attr_offset]
                attr_type = path_attr_data[attr_offset + 1]
                attr_offset += 2
                
                if flags & 0x10:
                    if attr_offset + 2 > len(path_attr_data):
                        break
                    attr_len = struct.unpack('>H', path_attr_data[attr_offset:attr_offset+2])[0]
                    attr_offset += 2
                else:
                    if attr_offset + 1 > len(path_attr_data):
                        break
                    attr_len = path_attr_data[attr_offset]
                    attr_offset += 1
                    
                if attr_offset + attr_len > len(path_attr_data):
                    break
                    
                attr_value = path_attr_data[attr_offset:attr_offset+attr_len]
                attr_offset += attr_len
                
                attr_info = {
                    'flags': flags,
                    'type': attr_type,
                    'value': attr_value
                }
                
                path_attributes.append(attr_info)
        
        offset = path_attr_end
        
        nlri = []
        while offset < len(payload):
            prefix_len = payload[offset]
            offset += 1
            
            prefix_bytes_needed = (prefix_len + 7) // 8
            
            if offset + prefix_bytes_needed > len(payload):
                break
                
            prefix_bytes = payload[offset:offset+prefix_bytes_needed] + b'\x00' * (4 - prefix_bytes_needed)
            prefix = socket.inet_ntoa(prefix_bytes)
            
            nlri.append((prefix, prefix_len))
            offset += prefix_bytes_needed
        
        return {
            'withdrawn': withdrawn_routes,
            'path_attributes': path_attributes,
            'nlri': nlri
        }

    def parse_notification_message(self, payload):
        if len(payload) < 2:
            return {'error': 'NOTIFICATION message too short'}
            
        error_code = payload[0]
        error_subcode = payload[1]
        error_data = payload[2:] if len(payload) > 2 else b''
        
        return {
            'error_code': error_code,
            'error_subcode': error_subcode,
            'error_data': error_data,
            'error_str': self.notification_error_to_string(error_code, error_subcode)
        }

    def bgp_type_to_string(self, msg_type):
        mapping = {
            BGP_OPEN: 'OPEN',
            BGP_UPDATE: 'UPDATE',
            BGP_NOTIFICATION: 'NOTIFICATION',
            BGP_KEEPALIVE: 'KEEPALIVE',
            BGP_ROUTE_REFRESH: 'ROUTE-REFRESH'
        }
        return mapping.get(msg_type, f"UNKNOWN({msg_type})")

    def notification_error_to_string(self, err_code, err_subcode):
        error_map = {
            ERR_MESSAGE_HEADER: "Message Header Error",
            ERR_OPEN_MESSAGE: "OPEN Message Error",
            ERR_UPDATE_MESSAGE: "UPDATE Message Error",
            ERR_HOLD_TIMER_EXPIRED: "Hold Timer Expired",
            ERR_FSM_ERROR: "Finite State Machine Error",
            ERR_CEASE: "Cease"
        }
        error_name = error_map.get(err_code, f"Unknown Error ({err_code})")
        
        if err_code == ERR_OPEN_MESSAGE:
            subcode_map = {
                OPEN_ERR_UNSUPPORTED_VERSION: "Unsupported Version Number",
                OPEN_ERR_BAD_PEER_AS: "Bad Peer AS",
                OPEN_ERR_BAD_BGP_IDENTIFIER: "Bad BGP Identifier",
                OPEN_ERR_UNSUPPORTED_OPTIONAL_PARAM: "Unsupported Optional Parameter",
                OPEN_ERR_AUTHENTICATION_FAILURE: "Authentication Failure",
                OPEN_ERR_UNACCEPTABLE_HOLD_TIME: "Unacceptable Hold Time",
                OPEN_ERR_UNSUPPORTED_CAPABILITY: "Unsupported Capability"
            }
            subcode_name = subcode_map.get(err_subcode, f"Unknown Subcode ({err_subcode})")
        else:
            subcode_name = f"Subcode {err_subcode}"
            
        return f"{error_name}: {subcode_name}"

    def perform_bgp_connection(self, **open_params):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((self.target_ip, self.target_port))
            
            open_msg = self.build_bgp_open(**open_params)
            sock.sendall(open_msg)
            
            response_data = b""
            start_time = time.time()
            
            while time.time() - start_time < self.timeout:
                try:
                    chunk = sock.recv(MAX_RESPONSE_SIZE)
                    if not chunk:
                        break
                    response_data += chunk
                    
                    messages = self.parse_bgp_messages(response_data)
                    
                    if any(msg['type'] == BGP_NOTIFICATION for msg in messages):
                        break
                        
                    got_open = any(msg['type'] == BGP_OPEN for msg in messages)
                    got_keepalive = any(msg['type'] == BGP_KEEPALIVE for msg in messages)
                    
                    if got_open and got_keepalive:
                        sock.sendall(self.build_bgp_keepalive())
                        self.session_established = True
                        break
                        
                except socket.timeout:
                    break
            
            messages = self.parse_bgp_messages(response_data)
            return bool(response_data), messages, sock
            
        except socket.error as e:
            self.log(f"Socket error during BGP connection: {str(e)}", "ERROR")
            try:
                sock.close()
            except:
                pass
            return False, [], None

    def test_session_establishment(self):
        self.log("Testing BGP session establishment...")
        
        success, messages, sock = self.perform_bgp_connection()
        
        if success:
            msg_types = [msg['type'] for msg in messages]
            
            if BGP_NOTIFICATION in msg_types:
                notification = next(msg for msg in messages if msg['type'] == BGP_NOTIFICATION)
                self.add_result("BGP Session Establishment", "FAIL",
                               f"Received NOTIFICATION: {notification['error_str']}", "MEDIUM")
            elif BGP_OPEN in msg_types and BGP_KEEPALIVE in msg_types:
                open_msg = next(msg for msg in messages if msg['type'] == BGP_OPEN)
                self.peer_open_params = open_msg
                
                self.add_result("BGP Session Establishment", "PASS",
                               f"Successfully established BGP session with peer AS {open_msg.get('as', 'unknown')}")
            else:
                self.add_result("BGP Session Establishment", "WARN",
                               f"Received unexpected response: {[msg['type_name'] for msg in messages]}", "LOW")
        else:
            self.add_result("BGP Session Establishment", "FAIL",
                          "Failed to establish BGP session, no valid response received", "HIGH")
        
        if sock:
            try:
                sock.close()
            except:
                pass

    def test_asn_handling(self):
        self.log("Testing ASN handling...")
        
        asn_test_cases = [
            (0, "Reserved ASN (0)", "HIGH"),
            (23456, "AS_TRANS (23456)", "MEDIUM"),
            (64496, "Reserved for documentation", "LOW"),
            (65551, "Private ASN range", "LOW"),
            (4200000000, "4-byte ASN", "MEDIUM"),
            (random.randint(65536, 4200000000), "Random 4-byte ASN", "LOW"),
        ]
        
        for asn, desc, severity in asn_test_cases:
            self.log(f"Testing ASN {asn} ({desc})...")
            
            success, messages, sock = self.perform_bgp_connection(my_as=asn)
            
            if success:
                notify_msgs = [m for m in messages if m['type'] == BGP_NOTIFICATION]
                
                if notify_msgs:
                    notification = notify_msgs[0]
                    err_code = notification.get('error_code')
                    err_subcode = notification.get('error_subcode')
                    
                    if err_code == ERR_OPEN_MESSAGE and err_subcode == OPEN_ERR_BAD_PEER_AS:
                        self.add_result(f"ASN Test ({desc})", "PASS",
                                      f"Correctly rejected ASN {asn} with Bad Peer AS notification")
                    else:
                        self.add_result(f"ASN Test ({desc})", "INFO",
                                      f"ASN {asn} rejected with notification: {notification['error_str']}")
                else:
                    if asn in [0, 23456]:
                        self.add_result(f"ASN Test ({desc})", "FAIL",
                                      f"Router incorrectly accepted reserved ASN {asn}", severity)
                    else:
                        self.add_result(f"ASN Test ({desc})", "PASS",
                                      f"Router accepted ASN {asn}")
            else:
                self.add_result(f"ASN Test ({desc})", "INFO",
                              f"Router did not respond to session with ASN {asn}")
            
            if sock:
                try:
                    sock.close()
                except:
                    pass

    def test_capability_handling(self):
        self.log("Testing capability handling...")
        
        capability_test_cases = [
            ([(CAP_4_OCTET_ASN, struct.pack('>I', 100000))], "4-byte ASN"),
            ([(CAP_MULTIPROTOCOL, struct.pack('>HBB', 2, 1, 1))], "IPv6 unicast"),
            ([(CAP_ROUTE_REFRESH, b'')], "Route refresh"),
            ([
                (CAP_4_OCTET_ASN, struct.pack('>I', 100000)),
                (CAP_ROUTE_REFRESH, b''),
                (CAP_GRACEFUL_RESTART, b'\x00\x00')
            ], "Multiple capabilities"),
            ([(99, b'\x01\x02\x03\x04')], "Unknown capability")
        ]
        
        for capabilities, desc in capability_test_cases:
            self.log(f"Testing capability: {desc}...")
            
            success, messages, sock = self.perform_bgp_connection(capabilities=capabilities)
            
            if success:
                notify_msgs = [m for m in messages if m['type'] == BGP_NOTIFICATION]
                
                if notify_msgs:
                    notification = notify_msgs[0]
                    err_code = notification.get('error_code')
                    err_subcode = notification.get('error_subcode')
                    
                    if err_code == ERR_OPEN_MESSAGE and err_subcode == OPEN_ERR_UNSUPPORTED_CAPABILITY:
                        self.add_result(f"Capability Test ({desc})", "INFO",
                                      f"Router explicitly rejected capability")
                    else:
                        self.add_result(f"Capability Test ({desc})", "INFO",
                                      f"Router rejected connection with notification: {notification['error_str']}")
                else:
                    open_msg = next((m for m in messages if m['type'] == BGP_OPEN), None)
                    if open_msg:
                        router_caps = []
                        for cap in open_msg.get('capabilities', []):
                            cap_code = cap.get('code')
                            if cap_code:
                                router_caps.append(cap_code)
                        
                        self.add_result(f"Capability Test ({desc})", "PASS",
                                       f"Router accepted connection with capability. Router capabilities: {router_caps}")
                    else:
                        self.add_result(f"Capability Test ({desc})", "PASS",
                                       "Router accepted connection with capability")
            else:
                self.add_result(f"Capability Test ({desc})", "INFO",
                              "Router did not respond to session with capability")
            
            if sock:
                try:
                    sock.close()
                except:
                    pass

    def test_malformed_messages(self):
        self.log("Testing malformed message handling...")
        
        malformation_test_cases = [
            ("marker", "Invalid marker", "HIGH"),
            ("length", "Invalid length field", "HIGH"),
            ("type", "Invalid message type", "MEDIUM"),
            ("open_version", "Invalid BGP version", "MEDIUM"),
            ("truncated", "Truncated message", "HIGH")
        ]
        
        success, messages, sock = self.perform_bgp_connection()
        
        if not success:
            self.add_result("Malformed Message Tests", "SKIP",
                          "Could not establish initial BGP session", "HIGH")
            return
            
        if sock:
            try:
                sock.close()
            except:
                pass
        
        for malform_type, desc, severity in malformation_test_cases:
            self.log(f"Testing malformation: {desc}...")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((self.target_ip, self.target_port))
                
                malformed_msg = self.build_malformed_message(malform_type)
                sock.sendall(malformed_msg)
                
                response_data = b""
                try:
                    while True:
                        chunk = sock.recv(MAX_RESPONSE_SIZE)
                        if not chunk:
                            break
                        response_data += chunk
                except socket.timeout:
                    pass
                
                messages = self.parse_bgp_messages(response_data)
                
                if messages:
                    notify_msgs = [m for m in messages if m['type'] == BGP_NOTIFICATION]
                    
                    if notify_msgs:
                        self.add_result(f"Malformed Message ({desc})", "PASS",
                                       f"Router correctly rejected malformed message with notification: {notify_msgs[0]['error_str']}")
                    else:
                        self.add_result(f"Malformed Message ({desc})", "FAIL",
                                       "Router accepted malformed message without sending NOTIFICATION", severity)
                else:
                    self.add_result(f"Malformed Message ({desc})", "WARN",
                                  "Router closed connection without sending NOTIFICATION", "LOW")
                
            except socket.error as e:
                self.add_result(f"Malformed Message ({desc})", "INFO",
                              f"Connection reset after malformed message: {str(e)}")
            
            try:
                sock.close()
            except:
                pass
            
            time.sleep(0.5)

    def test_route_filtering(self):
        self.log("Testing route filtering...")
        
        success, messages, sock = self.perform_bgp_connection()
        
        if not success or not self.session_established:
            self.add_result("Route Filtering Tests", "SKIP",
                          "Could not establish BGP session", "HIGH")
            return
        
        peer_as = None
        for msg in messages:
            if msg['type'] == BGP_OPEN:
                peer_as = msg.get('as')
                if 'real_as' in msg:
                    peer_as = msg['real_as']
                break
        
        if not peer_as:
            self.add_result("Route Filtering Tests", "SKIP",
                          "Could not determine peer AS", "MEDIUM")
            if sock:
                sock.close()
            return
        
        bogon_prefixes = [
            ("0.0.0.0", 8, "Default route"),
            ("10.0.0.0", 8, "RFC1918 private"),
            ("127.0.0.0", 8, "Loopback"),
            ("169.254.0.0", 16, "Link local"),
            ("172.16.0.0", 12, "RFC1918 private"),
            ("192.0.2.0", 24, "TEST-NET"),
            ("192.168.0.0", 16, "RFC1918 private"),
            ("224.0.0.0", 4, "Multicast"),
            ("240.0.0.0", 4, "Reserved")
        ]
        
        origin_attr = b'\x40\x01\x01\x00'
        as_path_attr = b'\x40\x02\x06\x02\x01\x00\x00\xfc\x00'
        next_hop_attr = b'\x40\x03\x04\xc0\x00\x02\x01'
        
        path_attributes = [origin_attr, as_path_attr, next_hop_attr]
        
        try:
            for prefix, length, desc in bogon_prefixes:
                self.log(f"Testing bogon prefix: {prefix}/{length} ({desc})...")
                
                nlri = [(prefix, length)]
                update_msg = self.build_bgp_update(path_attributes=path_attributes, nlri=nlri)
                sock.sendall(update_msg)
                
                time.sleep(0.1)
                
                response_data = b""
                try:
                    sock.settimeout(1)
                    response_data = sock.recv(MAX_RESPONSE_SIZE)
                except socket.timeout:
                    pass
                
                if response_data:
                    messages = self.parse_bgp_messages(response_data)
                    notify_msgs = [m for m in messages if m['type'] == BGP_NOTIFICATION]
                    
                    if notify_msgs:
                        self.add_result(f"Route Filtering ({desc})", "PASS",
                                       f"Router correctly rejected bogon prefix with notification: {notify_msgs[0]['error_str']}")
                        break
                    else:
                        self.add_result(f"Route Filtering ({desc})", "WARN",
                                       "Router sent response but did not reject bogon prefix with NOTIFICATION", "MEDIUM")
                else:
                    self.add_result(f"Route Filtering ({desc})", "FAIL",
                                   f"Router silently accepted bogon prefix {prefix}/{length}", "HIGH")
            
        except socket.error as e:
            self.add_result("Route Filtering", "INFO",
                          f"Connection reset during route filtering tests: {str(e)}")
        
        if sock:
            try:
                sock.close()
            except:
                pass

    def test_session_behavior(self):
        self.log("Testing BGP session behavior...")
        
        short_hold_time = 30
        success, messages, sock = self.perform_bgp_connection(hold_time=short_hold_time)
        
        if not success or not self.session_established:
            self.add_result("Session Behavior Tests", "SKIP",
                          "Could not establish BGP session", "HIGH")
            return
        
        negotiated_hold_time = None
        for msg in messages:
            if msg['type'] == BGP_OPEN:
                negotiated_hold_time = min(short_hold_time, msg.get('hold_time', 0))
                break
        
        if not negotiated_hold_time or negotiated_hold_time == 0:
            self.add_result("Hold Timer Test", "SKIP",
                          "Could not determine negotiated hold time or hold time is 0", "LOW")
        else:
            self.log(f"Testing hold timer enforcement (waiting for {negotiated_hold_time} seconds)...")
            
            hold_timer_start = time.time()
            notification_received = False
            
            try:
                wait_time = negotiated_hold_time + 5
                sock.settimeout(wait_time)
                
                while time.time() - hold_timer_start < wait_time:
                    try:
                        response = sock.recv(MAX_RESPONSE_SIZE)
                        if response:
                            messages = self.parse_bgp_messages(response)
                            for msg in messages:
                                if msg['type'] == BGP_NOTIFICATION:
                                    if msg.get('error_code') == ERR_HOLD_TIMER_EXPIRED:
                                        self.add_result("Hold Timer Test", "PASS",
                                                      "Router correctly sent Hold Timer Expired notification")
                                    else:
                                        self.add_result("Hold Timer Test", "INFO",
                                                      f"Router sent notification during hold timer test: {msg['error_str']}")
                                    notification_received = True
                                    break
                        if notification_received:
                            break
                    except socket.timeout:
                        break
                
                if not notification_received:
                    self.add_result("Hold Timer Test", "FAIL",
                                  "Router did not enforce hold timer by sending notification", "HIGH")
            
            except socket.error as e:
                elapsed = time.time() - hold_timer_start
                if elapsed >= negotiated_hold_time:
                    self.add_result("Hold Timer Test", "INFO",
                                  f"Connection reset after hold time ({elapsed:.1f}s), but no notification detected")
                else:
                    self.add_result("Hold Timer Test", "FAIL",
                                  f"Connection reset before hold time ({elapsed:.1f}s < {negotiated_hold_time}s)", "MEDIUM")
        
        if sock:
            try:
                sock.close()
            except:
                pass
        
        success, messages, sock = self.perform_bgp_connection()
        
        if success and self.session_established:
            self.log("Testing keepalive response behavior...")
            
            keepalive_responses = 0
            keepalive_failures = 0
            
            for i in range(3):
                try:
                    sock.sendall(self.build_bgp_keepalive())
                    
                    sock.settimeout(2)
                    response = b""
                    try:
                        response = sock.recv(MAX_RESPONSE_SIZE)
                    except socket.timeout:
                        pass
                    
                    if response:
                        messages = self.parse_bgp_messages(response)
                        if any(msg['type'] == BGP_KEEPALIVE for msg in messages):
                            keepalive_responses += 1
                    else:
                        keepalive_failures += 1
                    
                    time.sleep(1)
                    
                except socket.error:
                    keepalive_failures += 1
            
            if keepalive_responses > 0:
                self.add_result("Keepalive Response Test", "PASS",
                               f"Router responded to {keepalive_responses} of 3 keepalives")
            else:
                self.add_result("Keepalive Response Test", "INFO",
                               "Router did not respond to keepalives with keepalives")
        
        if sock:
            try:
                sock.close()
            except:
                pass

    def test_resource_limits(self):
        self.log("Testing resource limit handling...")
        
        resource_test_cases = [
            ("rapid_open", "Rapid TCP connection attempts", 10),
            ("large_updates", "Large UPDATE messages", 3),
            ("many_prefixes", "Many prefixes in single UPDATE", 1)
        ]
        
        for test_type, desc, iterations in resource_test_cases:
            self.log(f"Testing {desc}...")
            
            if test_type == "rapid_open":
                success_count = 0
                failure_count = 0
                
                for i in range(iterations):
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        sock.connect((self.target_ip, self.target_port))
                        success_count += 1
                        
                        sock.sendall(b"\xff" * 8)
                        sock.close()
                    except socket.error:
                        failure_count += 1
                
                self.add_result(f"Resource Test ({desc})", "INFO",
                              f"Router accepted {success_count} of {iterations} rapid connections")
                
                time.sleep(2)
                success, _, sock = self.perform_bgp_connection()
                
                if success:
                    self.add_result(f"Resource Test ({desc})", "PASS",
                                  "Router accepted normal connection after rapid connection test")
                else:
                    self.add_result(f"Resource Test ({desc})", "FAIL",
                                  "Router rejected normal connection after rapid connection test", "HIGH")
                
                if sock:
                    sock.close()
                
            elif test_type == "large_updates":
                success, messages, sock = self.perform_bgp_connection()
                
                if not success or not self.session_established:
                    self.add_result(f"Resource Test ({desc})", "SKIP",
                                  "Could not establish BGP session", "MEDIUM")
                    continue
                
                origin_attr = b'\x40\x01\x01\x00'
                as_path_attr = b'\x40\x02\x06\x02\x01\x00\x00\xfc\x00'
                next_hop_attr = b'\x40\x03\x04\xc0\x00\x02\x01'
                
                communities_data = b'\x01\x02\x03\x04' * 1024
                communities_attr = b'\xc0\x08' + struct.pack('>H', len(communities_data)) + communities_data
                
                path_attributes = [origin_attr, as_path_attr, next_hop_attr, communities_attr]
                
                try:
                    for i in range(iterations):
                        update_msg = self.build_bgp_update(
                            path_attributes=path_attributes,
                            nlri=[("203.0.113.0", 24)]
                        )
                        sock.sendall(update_msg)
                        
                        sock.settimeout(1)
                        response = b""
                        try:
                            response = sock.recv(MAX_RESPONSE_SIZE)
                        except socket.timeout:
                            pass
                        
                        if response:
                            messages = self.parse_bgp_messages(response)
                            notify_msgs = [m for m in messages if m['type'] == BGP_NOTIFICATION]
                            
                            if notify_msgs:
                                self.add_result(f"Resource Test ({desc})", "INFO",
                                              f"Router rejected large UPDATE with notification: {notify_msgs[0]['error_str']}")
                                break
                
                except socket.error as e:
                    self.add_result(f"Resource Test ({desc})", "INFO",
                                  f"Connection reset during large UPDATE test: {str(e)}")
                
                if sock:
                    sock.close()
                
                time.sleep(2)
                success, _, new_sock = self.perform_bgp_connection()
                
                if success:
                    self.add_result(f"Resource Test ({desc})", "PASS",
                                  "Router accepted normal connection after large UPDATE test")
                else:
                    self.add_result(f"Resource Test ({desc})", "FAIL",
                                  "Router rejected normal connection after large UPDATE test", "HIGH")
                
                if new_sock:
                    new_sock.close()
                
            elif test_type == "many_prefixes":
                success, messages, sock = self.perform_bgp_connection()
                
                if not success or not self.session_established:
                    self.add_result(f"Resource Test ({desc})", "SKIP",
                                  "Could not establish BGP session", "MEDIUM")
                    continue
                
                origin_attr = b'\x40\x01\x01\x00'
                as_path_attr = b'\x40\x02\x06\x02\x01\x00\x00\xfc\x00'
                next_hop_attr = b'\x40\x03\x04\xc0\x00\x02\x01'
                
                path_attributes = [origin_attr, as_path_attr, next_hop_attr]
                
                nlri = []
                for i in range(1000):
                    third_octet = (i // 256) % 256
                    fourth_octet = i % 256
                    nlri.append((f"203.0.{third_octet}.{fourth_octet}", 32))
                
                try:
                    update_msg = self.build_bgp_update(
                        path_attributes=path_attributes,
                        nlri=nlri
                    )
                    sock.sendall(update_msg)
                    
                    sock.settimeout(2)
                    response = b""
                    try:
                        response = sock.recv(MAX_RESPONSE_SIZE)
                    except socket.timeout:
                        pass
                    
                    if response:
                        messages = self.parse_bgp_messages(response)
                        notify_msgs = [m for m in messages if m['type'] == BGP_NOTIFICATION]
                        
                        if notify_msgs:
                            self.add_result(f"Resource Test ({desc})", "INFO",
                                          f"Router rejected UPDATE with many prefixes: {notify_msgs[0]['error_str']}")
                        else:
                            self.add_result(f"Resource Test ({desc})", "INFO",
                                          "Router accepted UPDATE with many prefixes")
                    else:
                        self.add_result(f"Resource Test ({desc})", "INFO",
                                      "Router silently accepted UPDATE with many prefixes")
                
                except socket.error as e:
                    self.add_result(f"Resource Test ({desc})", "INFO",
                                  f"Connection reset during many prefixes test: {str(e)}")
                
                if sock:
                    sock.close()
                
                time.sleep(2)
                success, _, new_sock = self.perform_bgp_connection()
                
                if success:
                    self.add_result(f"Resource Test ({desc})", "PASS",
                                  "Router accepted normal connection after many prefixes test")
                else:
                    self.add_result(f"Resource Test ({desc})", "FAIL",
                                  "Router rejected normal connection after many prefixes test", "HIGH")
                
                if new_sock:
                    new_sock.close()

    def print_results_summary(self):
        print("\n" + "=" * 80)
        print(f"BGP SECURITY ASSESSMENT SUMMARY FOR {self.target_ip}:{self.target_port}")
        print("=" * 80)
        
        high_severity = []
        medium_severity = []
        low_severity = []
        info = []
        pass_results = []
        
        for result in self.results:
            if result.result == "PASS":
                pass_results.append(result)
            elif result.severity == "HIGH":
                high_severity.append(result)
            elif result.severity == "MEDIUM":
                medium_severity.append(result)
            elif result.severity == "LOW":
                low_severity.append(result)
            else:
                info.append(result)
        
        if high_severity:
            print("\nHIGH SEVERITY ISSUES:")
            print("-" * 80)
            for result in high_severity:
                print(f"[{result.name}] {result.details}")
        
        if medium_severity:
            print("\nMEDIUM SEVERITY ISSUES:")
            print("-" * 80)
            for result in medium_severity:
                print(f"[{result.name}] {result.details}")
        
        if low_severity:
            print("\nLOW SEVERITY ISSUES:")
            print("-" * 80)
            for result in low_severity:
                print(f"[{result.name}] {result.details}")
        
        if pass_results:
            print("\nPASSING TESTS:")
            print("-" * 80)
            for result in pass_results:
                print(f"[{result.name}] {result.details}")
        
        if self.verbose and info:
            print("\nINFORMATIONAL RESULTS:")
            print("-" * 80)
            for result in info:
                print(f"[{result.name}] {result.details}")
        
        print("\nSUMMARY COUNTS:")
        print("-" * 80)
        print(f"Total Tests: {len(self.results)}")
        print(f"Passing: {len(pass_results)}")
        print(f"High Severity Issues: {len(high_severity)}")
        print(f"Medium Severity Issues: {len(medium_severity)}")
        print(f"Low Severity Issues: {len(low_severity)}")
        print(f"Informational Results: {len(info)}")
        print("=" * 80)

def main():
    parser = argparse.ArgumentParser(description="Enhanced BGP Security Assessment Tool")
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument("target_port", nargs="?", type=int, default=DEFAULT_PORT,
                       help=f"Target BGP port (default: {DEFAULT_PORT})")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT,
                       help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose output")
    parser.add_argument("-q", "--quiet", action="store_true",
                       help="Disable all output except final summary")
    
    args = parser.parse_args()
    
    tester = BGPSecurityTester(
        target_ip=args.target_ip,
        target_port=args.target_port,
        timeout=args.timeout,
        verbose=not args.quiet
    )
    
    tester.run_all_tests()

if __name__ == "__main__":
    main()
