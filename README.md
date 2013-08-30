# httpcache

The zero configuration caching man in the middling http(s) proxy

Goals:

* Stupid but easy to understand caching behaviour
* Easy to inspect cache
* Usable in transparent proxy configuration
* Man in the middle https connections using a CA certificate you generate
* Cache `apt-get update/upgrade`, `pip install` and `npm install`

### Note: The MITM feature (see: the openssl certificate commands) should only be used if you understand the security implications. Note that if you do this wrong you break the security of all https connections from your machine, including those from firefox or google chrome to your bank!

Usage:

	# Generate CA certificate for MITM'ing https connections
	$ openssl genpkey -algorithm rsa -out mitm-ca.key -pkeyopt rsa_keygen_bits:4096
	$ openssl req -new -x509 -days 365 -key mitm-ca.key -out mitm-ca.crt -subj "/O=httpcache\/$(whoami)/"

	# Trust yourself. But keep mitm-ca.key private, otherwise bye-bye bank details.
	$ sudo cp mitm-ca.crt /usr/local/share/ca-certificates/httpcache-tmp-mitm.crt
	$ sudo update-ca-certificates

	$ httpcache &
	2013/08/30 18:35:26 Serving on :3128

First wget: (note how wget doesn't complain about the invalid certificate)

	$ http_proxy=http://localhost:3128 https_proxy=http://localhost:3128 \
		wget https://google.com

	--2013-08-30 19:50:31--  https://google.com/
	Resolving localhost (localhost)... 127.0.0.1
	Connecting to localhost (localhost)|127.0.0.1|:3128... connected.
	2013/08/30 18:50:31 CONNECT //google.com:443
	2013/08/30 18:50:31 Took 4us to generate cert
	Proxy request sent, awaiting response... 2013/08/30 18:50:31 GET https://google.com:443/
	301 301 Moved Permanently
	Location: https://www.google.com/ [following]
	--2013-08-30 19:50:31--  https://www.google.com/
	Connecting to localhost (localhost)|127.0.0.1|:3128... connected.
	2013/08/30 18:50:31   -> Live: cache/google.com:443/index.html
	2013/08/30 18:50:31 CONNECT //www.google.com:443
	2013/08/30 18:50:31  --> served GET
	2013/08/30 18:50:31  --> served CONNECT
	2013/08/30 18:50:31 Took 390ms to generate cert
	Proxy request sent, awaiting response... 2013/08/30 18:50:32 GET https://www.google.com:443/
	302 302 Found
	Location: https://www.google.co.uk/?gws_rd=cr&ei=eOkgUuzcFo200QWri4G4Bw [following]
	--2013-08-30 19:50:32--  https://www.google.co.uk/?gws_rd=cr&ei=eOkgUuzcFo200QWri4G4Bw
	Connecting to localhost (localhost)|127.0.0.1|:3128... connected.
	2013/08/30 18:50:32   -> Live: cache/www.google.com:443/index.html
	2013/08/30 18:50:32  --> served GET
	2013/08/30 18:50:32  --> served CONNECT
	2013/08/30 18:50:32 CONNECT //www.google.co.uk:443
	2013/08/30 18:50:32 Took 353.422ms to generate cert
	Proxy request sent, awaiting response... 2013/08/30 18:50:32 GET https://www.google.co.uk:443/?gws_rd=cr&ei=eOkgUuzcFo200QWri4G4Bw
	200 200 OK
	Length: unspecified [text/html]
	Saving to: `index.html'

	    [<=>                                                             ] 0           --.-K/s              2013/08/30 18:50:33   -> Live: cache/www.google.co.uk:443/index.html?gws_rd=cr&ei=eOkgUuzcFo200QWri4G4Bw
	2013/08/30 18:50:33  --> served GET
	2013/08/30 18:50:33  --> served CONNECT
	    [ <=>                                                            ] 10,509      --.-K/s   in 0.05s   

	2013-08-30 19:50:33 (194 KB/s) - `index.html' saved [10509]

Second wget (note cached: lines).

	--2013-08-30 19:50:39--  https://google.com/
	Resolving localhost (localhost)... 127.0.0.1
	Connecting to localhost (localhost)|127.0.0.1|:3128... connected.
	2013/08/30 18:50:39 CONNECT //google.com:443
	2013/08/30 18:50:39 Took 5us to generate cert
	Proxy request sent, awaiting response... 2013/08/30 18:50:40 GET https://google.com:443/
	2013/08/30 18:50:40   -> Cached: cache/google.com:443/index.html
	301 301 Moved Permanently
	Location: https://www.google.com/ [following]
	2013/08/30 18:50:40  --> served GET
	2013/08/30 18:50:40  --> served CONNECT
	--2013-08-30 19:50:40--  https://www.google.com/
	Connecting to localhost (localhost)|127.0.0.1|:3128... connected.
	2013/08/30 18:50:40 CONNECT //www.google.com:443
	2013/08/30 18:50:40 Took 1us to generate cert
	Proxy request sent, awaiting response... 2013/08/30 18:50:40 GET https://www.google.com:443/
	2013/08/30 18:50:40   -> Cached: cache/www.google.com:443/index.html
	2013/08/30 18:50:40  --> served GET
	2013/08/30 18:50:40  --> served CONNECT
	302 302 Found
	Location: https://www.google.co.uk/?gws_rd=cr&ei=eOkgUuzcFo200QWri4G4Bw [following]
	--2013-08-30 19:50:40--  https://www.google.co.uk/?gws_rd=cr&ei=eOkgUuzcFo200QWri4G4Bw
	Connecting to localhost (localhost)|127.0.0.1|:3128... connected.
	2013/08/30 18:50:40 CONNECT //www.google.co.uk:443
	2013/08/30 18:50:40 Took 2us to generate cert
	Proxy request sent, awaiting response... 2013/08/30 18:50:40 GET https://www.google.co.uk:443/?gws_rd=cr&ei=eOkgUuzcFo200QWri4G4Bw
	2013/08/30 18:50:40   -> Cached: cache/www.google.co.uk:443/index.html?gws_rd=cr&ei=eOkgUuzcFo200QWri4G4Bw
	2013/08/30 18:50:40  --> served GET
	2013/08/30 18:50:40  --> served CONNECT
	200 200 OK
	Length: unspecified [text/html]
	Saving to: `index.html.1'

	    [ <=>                                                            ] 10,509      --.-K/s   in 0s      

	2013-08-30 19:50:40 (119 MB/s) - `index.html.1' saved [10509]


