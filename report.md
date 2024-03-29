## 0. Setup
### 0.1 In TMUX Window
1. Left = vm_0 = 192.168.15.4 = localhost:23333 = victim DNS Server = Apollo
2. Right Top = vm_3 = 192.168.15.7 = localhost:23335 = Attacker = dns_attacker
3. Right Bottom = jin511_ = 192.168.15.5 = localhost:23334 = User = dns_user

## 1. Remote Cache Poisoning
1. see `commit 42417bb9ce435c01727b8bf2af4f6e43248a2ca9` for how I Poison the cache of Apollo from the attacker's machine
    - Actually, `commit ba53c2eab735d558a817342ab9c91a8840bf6976` did a great improvement on the success probability, but MOST of my effort is in the previous commit.
2. see [here](./my_result.db), this is the poisoned DNS cache from Apollo (after I run ./udp <attack_IP> <server_IP> and poisoned the server successfully).
    - You can type `cat my_result.db | grep dnslab` to see the result of my poison.
3. Steps for having done these:
    1. restart the DNS Server on Apollo
    2. config the attacker machine, letting it use Apollo as the local DNS Server (by Configing the DHCP client on it)
        - actually, you can also do this similarly on the user's machine
    3. Send a non-exist url (`?????.example.edu`) from attacker machine to Apollo, and this is almost implemented in the original udp.c
    4. After 3., the attacker should pretend it's the real domain server `example.edu.`, build tons of fake responses and send to Apollo, hoping one's Transaction ID is identical to `what Apollo actually sends to the real domain server`. This is implemented by me in the newest udp.c
        - We need to know the real ip of the real domain server `example.edu.`, and it's easy to use `dig` command to do so.
        - We need to know all the details of the DNS protocol and how to build a fake one, actually I combine the information from both lab_description_pdf and the wireshark package capture results.
    5. Go back to 3., repeat this process for several times. Actually after my calculating, in `commit ba53c2eab735d558a817342ab9c91a8840bf6976` I implement a method which has roughly `80%` possibility to poison the DNS Server's Cache each time you run ./udp <attack_IP> <server_IP>.


## 2. Result Verification
1. see [here](./dig_result_from_user), this is the dig result from the user's machine.
2. Steps for having done these:
    - config the Apollo, when meeting `ns.dnslabattacker.net.`, just go to `192.168.15.7` (not `192.168.15.6`, because of my VM's configure)
    - config the attacker's machine, build a rule of which (fake) ip address to return when the user sends a dns lookup like `<??>.example.edu` to Apollo (and then attacker)
    - `dig www.example.edu` on user's machine

### 2.1 Why the additional record will not be accepted by Apollo?
- since it's against the Bailiwick checking. `ns.dnslabattacker.net.` is not in domain `example.edu.`

## 3. Attacking users
1. Modify content in attacker's machine's `/var/www/index.html` (You can contain some malicious contents, but I didn't)
2. Add a new rule `test    IN      A       192.168.15.7` in attacker's machine's `/etc/bind/example.edu.db`, and then restart the attacker's DNS server.
3. What happened?
    1. When the user type `wget http://test.example.edu`, it first sends DNS query to Apollo (cause Apollo is its local DNS Server)
    2. Since the DNS Cache of Apollo is already poisoned, it recv DNS query `test.example.edu`, and wants `ns.dnslabattacker.net.` can answer the ip. Because we have already modified `/etc/bind/named.conf.default-zones` on Apollo, this query will be directed to attacker (192.168.15.7)
    3. Then attacker reply "The IP for `test.example.edu` is 192.168.15.7"
    4. Then the user send HTTP request to 192.168.15.7, thus finishing our attacking.


