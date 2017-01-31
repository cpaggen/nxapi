#!/usr/bin/env python
#
# pretty simple code that make a aaaUser class query to NXAPI (REST/object style)
# then code brutally deletes all DNs returned (customer request - I do what I am told :)
#
# cpaggen Jan 2017
# 
# this program released under GPLv3 licensing terms: https://www.gnu.org/licenses/gpl.txt
#

import requests
import sys, pprint, json

http_header = {}
url_dict = {}

def getCookie(ip_addr, username, password):
    url = 'http://'+ip_addr+'/api/aaaLogin.xml'
    http_header["Host"]=ip_addr
    xml_string = "<aaaUser name='%s' pwd='%s'/>" % (username, password)
    try:
        req = requests.post(url=url, data=xml_string, headers=http_header)
    except:
        print 'Failed to obtain auth cookie: %s' % (e)
        sys.exit(1)
    else:
        cookie=req.headers['Set-Cookie']
        return cookie

def genericGetRequest(ip_addr, cookie, apiurl, verb, desc):
    print desc
    url = 'http://'+ip_addr+apiurl
    http_header["Cookie"]=cookie
    http_header["Host"]=ip_addr
    try:
        req = requests.request(verb, url=url, headers=http_header)
    except:
        print "There is a problem with the {} request!".format(verb)
    else:
        return(req)

def main():
    if len(sys.argv) != 4:
        print "Usage: {} <ip> <username> <password>".format(sys.argv[0])
        sys.exit(1)
    else:
        ip,user,password = sys.argv[1:]

    cookie=getCookie(ip, user, password)

    if cookie:
        users = ''
        dn = ''
        print "User is logged in. Auth-cookie is  %s\n" % cookie
        url_dict["/api/node/class/aaaUser.json?"]="Getting list of users"

        for url,desc in url_dict.iteritems():
            users = genericGetRequest(ip, cookie, url, 'GET', desc)
            users = users.json()
        print "Found {} local users".format(len(users['imdata']))
        for user in users['imdata']:
            dn = user['aaaUser']['attributes']['dn']
            print "\tdeleting {}".format(dn)
            url = '/api/mo/' + dn + '.json'
            resp = genericGetRequest(ip, cookie, url, 'DELETE', '')
            print resp

        print "\n\ndone!"

if __name__ == '__main__':
    sys.exit(main())
