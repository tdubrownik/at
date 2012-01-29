debug = True

port = 8080

db = './at.db'
cap_file = './dhcp-cap'
lease_file = './leases'
lease_offset = 60 * 20
timeout = 3000

wiki_url = 'http://hackerspace.pl/wiki/doku.php?id=people:%(login)s:start'

claimable_prefix = '' #'192.168.1.'
claimable_exclude = [
#    '127.0.0.1',
]

secret_key = 'adaba'
