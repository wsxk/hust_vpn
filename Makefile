all: 
	gcc -o superfast_server my_superfast_vpn_server.c -lssl -lcrypto  -lcrypt -lpthread
	gcc -o superfast_client my_superfast_vpn_client.c -lssl -lcrypto 

clean: 
	rm -f superfast_server superfast_client
	rm -f *~

