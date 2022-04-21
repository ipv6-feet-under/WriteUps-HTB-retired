#!/usr/bin/env python3

import requests
import urllib3

urllib3.disable_warnings()

cookies = {'XSRF-TOKEN':'eyJpdiI6Ik1IdlV4T1g1NTRjMWxFNEg2M1NBVnc9PSIsInZhbHVlIjoicTV4RzRSUHVETzllMW8xeGg2RllDWjM0N0tzRlFIbWtsY1RSdGxSYkJSQ3ZMSnhPMkF1dnA0aVpIR3JKTzF4VnYzeEJ0VGkxUEpSMXp5NWdyNWV5YnB1SDNkR1BEQVNHL0RSdkVySnZpTkhiYU9odXpqSFlUMXR6U3Niakp1ZjgiLCJtYWMiOiIxNTE2MDdkMGIwMGQwNjdmMmM1NTdiYmNkMzFkNzhlZDQyMTQyNmRmMjJiNjk0OTY1YmUxZTlmMWUwMjRlOTA3In0%3D','earlyaccess_session':'eyJpdiI6IkdPRklSaXVaeXkya0VqMEdua3NzSHc9PSIsInZhbHVlIjoianliRHplL3pmTTVPSXdNbUU2VzNMYUpxaXV2TFNFSWpOd1RORUFhOVRIbXYrdVB4QSszb2ZUNkVjb2x4TythVU5tZUUwYlExcTNtRGR4L3ZhME5PV09PQVAzRGhVQzByYmtGWFpOZXhwS1dYWDlrTkthMjFKTGN4cGdtSm1ZWUQiLCJtYWMiOiJkYjQ2NDg1M2UzYTUyZjM0YzEyZTVkOTAyN2ZhYmU4OGZlMzAwMWY5ZWY1NTI0MjIwZjJlZTMxMzE0NzI0ODE5In0%3D'}

alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
num = "0123456789"


def calc_cs(input) -> int:
        gs = input.split('-')[:-1]
        return sum([sum(bytearray(g.encode())) for g in gs])


key = ""

def keygen():
    for i in alpha:
        for j in alpha:
            for k in num:
                key = r"KEY12-1K1H1-XP{}{}{}-GAMD2-".format(i,j,k)
                final_key = (key + str(calc_cs(key)))
                r=requests.post('https://earlyaccess.htb/key/verify', data = {'_token':'Ppebb2RE0GrchE8HkwLDyTBQO8tbHZ1uyLpAYSv2', 'key':final_key}, cookies=cookies, verify=False)
                print(final_key + ' ' + str(len(r.text)).replace("13039","invalid"))

keygen()