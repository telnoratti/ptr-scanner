# ptr-scanner
PTR scanner to enumerate addresses using the NXDOMAIN/NOERROR trick

# Usage
Specify the prefix as a positional argument and DNS servers with `-s` flags. The `-r` option will rate limit X requests per second (not including retries).

    ./ptr-scanner 2001:db8::/32 -s 1.1.1.1 -s 8.8.8.8 -r 2000
  
