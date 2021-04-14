# SonicOS API script does the following:
# Log in
# Pull site to site VPN Policies
# Edit each policy to enable the "Disable IPsec Anti-Replay" option.
# Push the change back to SonicOS
# Commit the changes#
#

# Notes:
# anti_replay will be True in VPN config if the "Disable IPsec Anti-Replay" is unchecked/disabled in the GUI.
# anti_replay will be False in VPN config if the "Disable IPsec Anti-Replay" is checked/enabled in the GUI.


# Imports
import requests
import json
import base64
import urllib3
import getpass
from urllib3 import exceptions
from collections import OrderedDict


# Firewall IP/port for SonicOS API
fw = input("Enter the target firewall URL and port (Example: https://192.168.0.3:450): ")
admin_username = input("Enter the management username: ")
admin_password = getpass.getpass("Enter your administrator password: ")

# Hide the certificate warnings.
urllib3.disable_warnings(exceptions.InsecureRequestWarning)


# Good headers to use with SonicOS API.
good_headers = OrderedDict([
	('Accept', 'application/json'),
	('Content-Type', 'application/json'),
	('Accept-Encoding', 'application/json'),
	('charset', 'UTF-8')])


# Headers to use for authentication.
# Not used right now, but kept for my own notes.
#auth_headers_backup = OrderedDict([
#	('Accept', 'application/json'),
#	('Content-Type', 'application/json'),
#	('Accept-Encoding', 'application/json'),
#	('charset', 'UTF-8'),
#	('Authorization', 'Basic dddddddddddddddddddddddddd')])


# Print response information
def print_response_info(resp):
	print("\n========================")
	print("Req Headers", resp.request.headers)
	print("Request:", resp.request, "--> Status Code:", resp.status_code, resp.reason)
	print("Headers:", resp.headers)
#	print("Text:", f"Type {type(resp.content)}", resp.content)
	print("JSON:", f"Type {type(resp.json())}", resp.json())
#	resp_dict = resp.json()
	print("========================\n")


# Encode credentials
def encoded_credentials(user_name, password):
	user_name = bytes(user_name, 'utf-8')
	password = bytes(password, 'utf-8')
	encoded_credentials = base64.b64encode(user_name + b":" + password)
	encoded_credentials = encoded_credentials.decode('utf-8')
	return encoded_credentials


# Create the admin session and return a session object for later use.
def create_admin_session(firewall, admin_user, admin_password):
	# Headers
	auth_headers = OrderedDict([
		('Accept', 'application/json'),
		('Content-Type', 'application/json'),
		('Accept-Encoding', 'application/json'),
		('charset', 'UTF-8'),
		('Authorization', f'Basic {encoded_credentials(admin_user, admin_password)}')])

	# Create a session and POST a login.
	session = requests.Session()
	auth_resp = session.post(firewall + '/api/sonicos/auth', headers=auth_headers, verify=False)
	print_response_info(auth_resp)
	# Return a session object
	return session


# Gets the list of site to site VPN Policies and modifies the required settings.
# Returns the vpn_dictionary object with the VPN policy configuration modified.
def get_modify_s2s_ipv4_policies(session):
	# Get all of the site to site VPN policies/config.
	#resp = session.get(fw + '/api/sonicos/vpn/policies/ipv4/site-to-site', headers=auth_headers, verify=False)
	resp = session.get(fw + '/api/sonicos/vpn/policies/ipv4/site-to-site', headers=good_headers, verify=False)

	# Create a dictionary from the JSON response
	vpn_dictionary = resp.json()

	# Print number of VPN Policies returned
	print("Number of VPN Policies returned:", len(vpn_dictionary["vpn"]["policy"]))
	print()

	# Some test prints
	#print(vpn_dictionary["vpn"]["policy"][1]["ipv4"]["site_to_site"]["name"])
	#print(vpn_dictionary["vpn"]["policy"][1]["ipv4"]["site_to_site"]["keep_alive"])

	vpn_counter = 0
	# Iterate through the policies.
	for policy in vpn_dictionary["vpn"]["policy"]:
		# Print policy name
		print(f'--> Policy name: {policy["ipv4"]["site_to_site"]["name"]}')
#		# Check if the IPSec Primary Gateway is 0.0.0.0
#		if policy["ipv4"]["site_to_site"]["gateway"]["primary"] == "0.0.0.0":
#			# Policies with 0.0.0.0 cannot toggle keep alive.
#			print(f'----> ({policy["ipv4"]["site_to_site"]["name"]}): Primary IPSec Gateway is 0.0.0.0. Keep alive cannot be toggled.')
#		else:
		# Print the current setting value.
		print("Current 'Disable IPsec Anti-Replay' setting:", policy["ipv4"]["site_to_site"]["anti_replay"])
		# If "Disable IPsec Anti-Replay" is disabled/unchecked (anti_replay = True), change it to False.
		# Print the new setting value.
		if policy["ipv4"]["site_to_site"]["anti_replay"] is True:
			policy["ipv4"]["site_to_site"]["anti_replay"] = False
			print("New Keep Alive setting:", policy["ipv4"]["site_to_site"]["anti_replay"])
		print()
		#print(f"\n----- {vpn_counter} -----")
		vpn_counter += 1
	return vpn_dictionary


# Put the modified VPN Policies back into SonicOS config.
def put_modified_s2s_vpn_policy_config(session, vpn_dictionary):
	# PUT vpn_dictionary back
	resp = session.put(fw + '/api/sonicos/vpn/policies/ipv4/site-to-site', headers=good_headers, json=vpn_dictionary, verify=False)
	print_response_info(resp)


# Put the modified VPN Policies back into SonicOS config (one by one).
def put_modified_s2s_vpn_policy_config_iterated(session, vpn_dictionary):
	# PUT vpn_dictionary back in one policy at a time.
	# For each policy in the vpn_dictionary
	index = 0
	for policy in vpn_dictionary["vpn"]["policy"]:
		vpn_policy_name = policy["ipv4"]["site_to_site"]["name"]
		policy = {"vpn": {"policy": [ policy ]}}
		# PUT the VPN Policy configuration back to SonicOS by Policy name.
		resp = session.put(f'{fw}/api/sonicos/vpn/policies/ipv4/site-to-site/name/{vpn_policy_name}', headers=good_headers, json=policy, verify=False)
		print_response_info(resp)
		index += 1


# Gets the list of tunnel interface site to site VPN Policies and modifies the required settings.
# Returns the vpn_dictionary object with the VPN policy configuration modified.
def get_modify_ti_s2s_ipv4_policies(session):
	# Get all of the site to site VPN policies/config.
	#resp = session.get(fw + '/api/sonicos/vpn/policies/ipv4/site-to-site', headers=auth_headers, verify=False)
	resp = session.get(fw + '/api/sonicos/vpn/policies/ipv4/tunnel-interface', headers=good_headers, verify=False)

	# Create a dictionary from the JSON response
	ti_vpn_dictionary = resp.json()

	# Print number of VPN Policies returned
#	print("Number of VPN Policies returned:", len(ti_vpn_dictionary["vpn"]["policy"]))
	print()
	print()
	print(ti_vpn_dictionary)
	print()
	print()

	vpn_counter = 0
	# Iterate through the policies.
	for policy in ti_vpn_dictionary["vpn"]["policy"]:
		# Print policy name
		print(f'--> Policy name: {policy["ipv4"]["tunnel_interface"]["name"]}')
#		# Check if the IPSec Primary Gateway is 0.0.0.0
#		if policy["ipv4"]["tunnel_interface"]["gateway"]["primary"] == "0.0.0.0":
#			# Policies with 0.0.0.0 cannot toggle keep alive.
#			print(f'----> ({policy["ipv4"]["tunnel_interface"]["name"]}): Primary IPSec Gateway is 0.0.0.0. Keep alive cannot be toggled.')
#		else:
		# Print the current setting value.
		print("Current 'Disable IPsec Anti-Replay' setting:", policy["ipv4"]["tunnel_interface"]["anti_replay"])
		# If "Disable IPsec Anti-Replay" is disabled/unchecked (anti_replay = True), change it to False.
		# Print the new setting value.
		if policy["ipv4"]["tunnel_interface"]["anti_replay"] is True:
			policy["ipv4"]["tunnel_interface"]["anti_replay"] = False
			print("New 'Disable IPsec Anti-Replay' setting:", policy["ipv4"]["tunnel_interface"]["anti_replay"])
		print()
		#print(f"\n----- {vpn_counter} -----")
		vpn_counter += 1
	return ti_vpn_dictionary


# Put the modified VPN Policies back into SonicOS config (all at once).
def put_modified_ti_vpn_policy_config(session, vpn_dictionary):
	# PUT vpn_dictionary back
	resp = session.put(fw + '/api/sonicos/vpn/policies/ipv4/tunnel-interface', headers=good_headers, json=vpn_dictionary, verify=False)
	print_response_info(resp)


# Put the modified VPN Policies back into SonicOS config (one by one).
def put_modified_ti_vpn_policy_config_iterated(session, vpn_dictionary):
	# PUT vpn_dictionary back in one policy at a time.
	# For each policy in the vpn_dictionary
	index = 0
	for policy in vpn_dictionary["vpn"]["policy"]:
		vpn_policy_name = policy["ipv4"]["tunnel_interface"]["name"]
		policy = {"vpn": {"policy": [ policy ]}}
		# PUT the VPN Policy configuration back to SonicOS by Policy name.
		resp = session.put(f'{fw}/api/sonicos/vpn/policies/ipv4/tunnel-interface/name/{vpn_policy_name}', headers=good_headers, json=policy, verify=False)
		print_response_info(resp)
		index += 1


# Main function to run when program is launched.
def main():
	# Request credentials and target firewall before proceeding.

	# Create the session
	session = create_admin_session(fw, admin_username, admin_password)


# Site to Site VPNs
	# Get the VPN Policy configuration. Modify it. Return the modified VPN Policy configuration.
	vpn_dictionary = get_modify_s2s_ipv4_policies(session)

	# Put modified VPN Policies back to SonicOS.
	put_modified_s2s_vpn_policy_config_iterated(session, vpn_dictionary)


# Tunnel Interface VPNs
	# Get the TI VPN configuration. Modify it. Return the modified VPN Policy configuration.
#	ti_vpn_dictionary = get_modify_ti_s2s_ipv4_policies(session)

	# Put modified TI VPN Policies back to SonicOS.
#	put_modified_ti_vpn_policy_config_iterated(session, ti_vpn_dictionary)


# After changes are made, commit them.
	# Commit changes
	commited = session.post(fw + '/api/sonicos/config/pending', headers=good_headers, verify=False)
	print_response_info(commited)


# If program is launched directly
if __name__ == "__main__":
	main()
