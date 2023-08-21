# Cloudflare API call to check URI overrides

import http.client
import json

# prompt user for the account id

def get_account_id():  
    
    account_id = input("Please enter the Account id: ")
    return account_id

# prompt user for X-Auth-Email  

def get_auth_email():
    auth_email = input("Please enter the X-Auth-Email: ")
    return auth_email

# prompt user for Auth Key  

def get_auth_key():
    auth_key = input("Please enter the X-Auth-Key: ")
    return auth_key


# main loop for getting checking the WAF overrides
def check_waf_override(auth_email, auth_key, zone_ids):
    
  # print to screen advice that the api call has been made successfully and here are the results
  print("API call to check URI overrides has been made successfully. Results: ")
  # loop through each of the zone id's in the list and check the waf override

  for single_zone_id in zone_ids:  
    make_request(single_zone_id, auth_email, auth_key)

  print(">>> Zone list complete.")

# make the request with the zone identifier present in the URL with 
def make_request(single_zone_id, auth_email, auth_key):
    conn = http.client.HTTPSConnection("api.cloudflare.com")
    headers = {
        'Content-Type': "application/json",
        'X-Auth-Email': auth_email,
        'X-Auth-Key': auth_key
    }
    
    try:
        conn.request("GET", f"/client/v4/zones/{single_zone_id}/firewall/waf/overrides", headers=headers)
        res = conn.getresponse()
        data = res.read()
    except Exception as e:
        print(f"An error occurred while making the request: {e}")
        conn.close()
        return

    try:
        response_json = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as e:
        print(f"An error occurred while decoding the JSON response: {e}")
        conn.close()
        return
    
    print(response_json)

    conn.close()

# make an api call to get the list of zone id's from the account  
def get_zone_ids(auth_email, auth_key, account_id):
    conn = http.client.HTTPSConnection("api.cloudflare.com")
    headers = {
        'Content-Type': "application/json",
        'X-Auth-Email': auth_email,
        'X-Auth-Key': auth_key
    }
    zone_ids = []
    page = 1

    while True:
        try:
            conn.request("GET", f"/client/v4/zones?account.id={account_id}&page={page}&per_page=20", headers=headers)
            res = conn.getresponse()
            data = res.read()
        except Exception as e:
            print(f"An error occurred while making the request: {e}")
            conn.close()
            return []

        try:
            response_json = json.loads(data.decode("utf-8"))
            if not response_json['success']:
                print("Error(s) occurred:")
                for error in response_json['errors']:
                    print(f"Code: {error['code']}, Message: {error['message']}")
                conn.close()
                return []
            
        except (json.JSONDecodeError, ValueError) as e:
            print(f"An error occurred while decoding the JSON response: {e}")
            conn.close()
            return []

        if response_json['result'] is not None:
            zone_ids += [zone['id'] for zone in response_json['result']]

        if response_json['result_info']['total_pages'] > page:
            page += 1
        else:
            break

    print("API call to get the list of zone id's from the account has been made successfully. Results:")
    print(zone_ids)

    conn.close()

    return zone_ids

# main function

def main():
    account_id = get_account_id()
    auth_email = get_auth_email()
    auth_key = get_auth_key() 

    # call to loop through zones
    zone_ids = get_zone_ids(auth_email, auth_key, account_id)

    # loop through the list of zone id's and check for WAF overrides
    check_waf_override(auth_email, auth_key, zone_ids)
    
if __name__ == "__main__":
    main()
