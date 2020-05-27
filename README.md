# fullcone-nginx

Full-cone NAT for Linux implemented in user mode with Nginx as TCP forward proxy.

## How to Use

On the router that performs NAT:

### Install Package

* install Nginx with stream module enabled
* install conntrack user mode program (`apt install conntrack` for Debian)
* install python3

### Configure Nginx

In your nginx config file:

```nginx
stream {
    include /tmp/nginx-fullcone.conf;
}
```

### Enable NAT Using iptables/nft

```bash
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### Run Script

To read conntrack flow table, root or CAP_NET_ADMIN is needed.

```bash
python3 fullcone.py \
    --nginx-conf /tmp/fullcone-nginx.conf \
    --nginx-reload-command "/bin/systemctl reload nginx" \
    --conntrack-bin-path /usr/sbin/conntrack \
    --allowed-network 192.168.25.44/32 \
    --allowed-network 192.168.26.0/24 \
    --additional-conf "tcp_nodelay on;"
```

Explict specification of network to enable full cone NAT is needed, to save port space usage.

You can also run a dedicated Nginx instance, so frequent reloading does not impact your main Nginx deployment.

## How Does It Work

The python script reads conntrack event, and for each iptables NAT-ed connection, it creates a corresponding Nginx server block, to forward income connection. After conig file is updated, it reloads Nginx.

## Other Projects That Implement Full-Cone NAT on Linux

* https://github.com/Chion82/netfilter-full-cone-nat
* https://github.com/claw6148/ConeNATd
* https://github.com/andrsharaev/xt_NAT
