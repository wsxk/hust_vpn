#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <pthread.h>
#include <shadow.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <crypt.h> //client verify
#include <memory.h>


/* define HOME to be dir for key and cert files... */
#define HOME	"./openssl_sel_made/"

/* Make these what you want for cert & key files */
#define SERVER_CERTF HOME"server.crt"
#define SERVER_KEYF	HOME"server.key"
#define CACERT	HOME"ca.crt"
#define SERVER_PORT 4433
#define BUFFER_SIZE 2000

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)	if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }1

struct para{
	SSL_CTX * ctx;
	int client_sock;
};

pthread_mutex_t mutex;

void welcome_ui(void);
SSL_CTX * server_ssl_init(); // initialize the server ssl_ctx .
int setup_tcp_server(); // set up tcp socket
int accept_tcp_client(int listen_sock);// ret a client socket
void each_sock(void *arg);// process one sock
int verify(SSL * ssl); // judge whethernthe client is legal or not
void processRequest(SSL* ssl); //test
int create_tun_device(SSL* ssl, int* virtual_ip);// create tun device
void select_tunnel(SSL* ssl, int sock_fd, int tun_fd);//IO multiplexing

int main(int argc, char *argv[]){
    fprintf(stdout,"server start!\n");
    SSL_CTX * ctx = server_ssl_init();
	printf("ssl init finish\n");
    int listen_sock = setup_tcp_server();
	printf("listen socket finish\n");

	welcome_ui();

    while(1){
       int client_sock = accept_tcp_client(listen_sock);//get tcp connetc 
       if(client_sock==-1){
		   fprintf(stderr,"error! client_sock return fail!\n");
		   continue;
	   	}
		struct para client_arg;
		client_arg.client_sock=client_sock;
		client_arg.ctx=ctx;
		pthread_t tid;
		int ret = pthread_create(&tid, NULL, each_sock, (void*)&client_arg);
        if (ret != 0) {
            close(client_sock);
            perror("pthread_create failed");
            return -1;
        } 
    }
	close(listen_sock);
    SSL_CTX_free(ctx);
	end_ui();
    return 0;
}

void each_sock(void *arg){
	struct para tmp = *(struct para *)arg;
	SSL * ssl = SSL_new(tmp.ctx);// ssl socket
	SSL_set_fd(ssl,tmp.client_sock);// assigns a socket to a Secure Sockets Layer (SSL) structure. 
	int err = SSL_accept(ssl);//accepts a Secure Sockets Layer (SSL) session connection request from a remote client application. check whether the certificate is legal or not.
	if(err<=0){
		fprintf(stderr,"error when ssl accept!\n");
		return ;
	}
	printf("ssl accept!\n");
	// verify
	if(!verify(ssl)){
		SSL_shutdown(ssl);
        SSL_free(ssl);
        close(tmp.client_sock);
		fprintf(stderr,"error! verify failed!\n");
		return;
	}
	printf("start create tun device\n");
	// device tun create
	int virtual_ip;
	int tun_fd = create_tun_device(ssl,&virtual_ip);
	if(tun_fd==-1){
		fprintf(stderr,"error! create tun_device failed!\n");
		return;
	}
	//send vitual IP
	char buf[10];
    sprintf(buf,"%d",virtual_ip);
    printf("send virtual IP: 192.168.53.%s/24\n",buf);
    SSL_write(ssl,buf,strlen(buf)+1);
	//IO Multiplexing
	select_tunnel(ssl,tmp.client_sock,tun_fd);

	// shun down
	SSL_shutdown(ssl);
    SSL_free(ssl);
    close(tmp.client_sock);
	return ;
}

void select_tunnel(SSL* ssl, int sock_fd, int tun_fd){
	char buf[BUFFER_SIZE];
	int len;
	while(1){
		fd_set read_fd;// bitmap
		FD_ZERO(&read_fd);
		FD_SET(sock_fd,&read_fd);
		FD_SET(tun_fd,&read_fd);
		select(FD_SETSIZE,&read_fd,NULL,NULL,NULL);
		// target -> client
		if(FD_ISSET(tun_fd,&read_fd)){
			memset(buf,0,strlen(buf));
			len = read(tun_fd,buf,BUFFER_SIZE);
			buf[len] = '\0';
			SSL_write(ssl,buf,len);
		}
		// client -> target
		if(FD_ISSET(sock_fd,&read_fd)){
			memset(buf,0,strlen(buf));
			len = SSL_read(ssl,buf,BUFFER_SIZE);
			if(len==0){
				fprintf(stderr,"the ssl socket close!\n");
				return;
			}
			buf[len]='\0';
			write(tun_fd,buf,len);
		}
	}
}

int create_tun_device(SSL* ssl, int* virtual_ip){
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    //IFF_TUN:create a tun device
    //IFF_NO_PI:Do not provide packet information
  
    //create a tun device
    //find a name. lock
    pthread_mutex_lock(&mutex);
    int tunfd = open("/dev/net/tun", O_RDWR);
    pthread_mutex_unlock(&mutex);
    if (tunfd == -1) {
        fprintf(stderr,"error! open TUN failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }

    //register device work-model
    int ret = ioctl(tunfd, TUNSETIFF, &ifr);
    if (ret == -1) {
        fprintf(stderr,"error! setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }

    //tun id
    int tunId = atoi(ifr.ifr_name+3);
    if(tunId == 127) {
        fprintf(stderr,"error! exceed the maximum number of clients!\n");
        return -1;
    }

    //client_virtual_ip=tunID+127,target_virtual_ip=tunID+1
    char cmd[60];
    sprintf(cmd,"sudo ifconfig tun%d 192.168.53.%d/24 up",tunId,tunId+1);
    //route config
    system(cmd);
    sprintf(cmd,"route add -host 192.168.53.%d tun%d",tunId+127,tunId); // target -> client route
	system(cmd);
    system("sudo sysctl net.ipv4.ip_forward=1");

    *virtual_ip = tunId + 127;   //client_virtual_ip
    return tunfd;
}

int verify(SSL * ssl){
	// username and password
	char user_message[]="Please input username: ";
	SSL_write(ssl,user_message,strlen(user_message)+1);// writes application data across a Secure Sockets Layer (SSL) session.
	char username[BUFFER_SIZE];
	int user_len=SSL_read(ssl,username,BUFFER_SIZE);
	char password_message[]="Please input password: ";
	SSL_write(ssl,password_message,strlen(password_message)+1);
	char password[BUFFER_SIZE];
	int password_len = SSL_read(ssl,password,BUFFER_SIZE);
	// check 
	struct spwd *pw = getspnam(username);    //get account info from shadow file
	if (pw == NULL){// the user doesn't exist
	    char no[] = "Client verify failed";
		printf("%s\n",no);
        SSL_write(ssl, no, strlen(no)+1);
		fprintf(stderr,"error! user doesn't exist\n");
		return 0; 
	} 
	char *epasswd = crypt(password, pw->sp_pwdp);//md5(password,salt)	
	if (strcmp(epasswd, pw->sp_pwdp)) {
		char no[] = "Client verify failed";
		printf("%s\n",no);
        SSL_write(ssl, no, strlen(no)+1);
		fprintf(stderr,"error! password\n");
		return 0;
	} 
    char yes[] = "Client verify succeed";
    printf("%s\n",yes);
    SSL_write(ssl, yes, strlen(yes)+1);
	return 1;
}


void processRequest(SSL* ssl) {
    char buf[1024];
    int len = SSL_read (ssl, buf, sizeof(buf));
    CHK_SSL(len);
    // buf[len] = '\0';
    printf("Received: %s\n",buf);

    // Construct and send the HTML page
    char html[] =
	"HTTP/1.1 200 OK\r\n"
	"Content-Type: text/html\r\n\r\n"
	"<!DOCTYPE html><html>"
	"<head><title>Hello World</title></head>"
	"<style>body {background-color: black}"
	"h1 {font-size:3cm; text-align: center; color: white;"
	"text-shadow: 0 0 3mm yellow}</style></head>"
	"<body><h1>Hello,HHY miniVPN!</h1></body></html>";
    len = SSL_write(ssl, html, strlen(html)+1);
    CHK_SSL(len);
}
int accept_tcp_client(int listen_sock){
	struct sockaddr_in clientAddr;
    size_t clientAddrLen = sizeof(struct sockaddr_in);
	int client_sock = accept(listen_sock, (struct sockaddr *)&clientAddr, &clientAddrLen);
	if(client_sock==-1){
		fprintf(stderr,"error accept client!\n");
		return -1;
	}
	fprintf(stdout,"get a connect request! s.ip is %s s.port is %d\n",inet_ntoa(clientAddr.sin_addr), clientAddr.sin_port);
	return client_sock;
}

void welcome_ui(void){
	fprintf(stdout,"loading...\n");
	fprintf(stdout,"******************************\n");
	fprintf(stdout,"******************************\n");
	fprintf(stdout,"**   S               S      **\n");
	fprintf(stdout,"**    U             U       **\n");
	fprintf(stdout,"**     P           P        **\n");
	fprintf(stdout,"**      E         E         **\n");
	fprintf(stdout,"**       R       R          **\n");
	fprintf(stdout,"**        F     F           **\n");
	fprintf(stdout,"**         A   A            **\n");
	fprintf(stdout,"**          S S             **\n");
	fprintf(stdout,"**           T         wsxk **\n");
	fprintf(stdout,"******************************\n");
	fprintf(stdout,"******************************\n");
}

SSL_CTX * server_ssl_init(){
    SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
	int err;

	// Step 0: OpenSSL library initialization 
	// This step is no longer needed as of version 1.1.0.
    SSL_library_init();//The SSL_library_init function registers the available ciphers and message digests.
    SSL_load_error_strings();// error information
    SSLeay_add_ssl_algorithms();

    // Step 1: SSL context initialization
    meth = SSLv23_server_method();//The SSLv23_server_method function indicates that the application is a server and supports Transport Layer Security version 1.0 (TLSv1.0), Transport Layer Security version 1.1 (TLSv1.1), and Transport Layer Security version 1.2 (TLSv1.2).
    ctx = SSL_CTX_new(meth); //creates a new SSL_CTX object as framework to establish TLS/SSL enabled connections.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); //sets the verification flags for ctx to be mode and specifies the verify_callback function to be used. If no callback function shall be specified, the NULL pointer can be used for verify_callback.
    SSL_CTX_load_verify_locations(ctx, CACERT, NULL);// set default locations for trusted CA certificates

    // Step 2: Set up the server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERTF, SSL_FILETYPE_PEM) <= 0) {//loads the certificate for use with Secure Sockets Layer (SSL) sessions using a specific context (CTX) structure.
        fprintf(stderr,"server cert use error!\n");
		ERR_print_errors_fp(stderr);
		exit(3);
	}
    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEYF, SSL_FILETYPE_PEM) <= 0) {// loads the private key for use with Secure Sockets Layer (SSL) sessions using a specific context (CTX) structure.
		fprintf(stderr,"server key use error!\n");
        ERR_print_errors_fp(stderr);
		exit(4);
	}
    if (!SSL_CTX_check_private_key(ctx)) {// verifies that the private key agrees with the corresponding public key in the certificate associated with a specific context (CTX) structure.
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(5);
	}

	return ctx;
}

int setup_tcp_server()
{
	struct sockaddr_in sa_server;
	int listen_sock;

	listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);//TCP SOCKET ipv4
	CHK_ERR(listen_sock, "socket");
	memset(&sa_server, '\0', sizeof(sa_server));
	sa_server.sin_family = AF_INET;//ipv4
	sa_server.sin_addr.s_addr = INADDR_ANY;// 0.0.0.0
	sa_server.sin_port = htons(SERVER_PORT);
	int err = bind(listen_sock, (struct sockaddr *) &sa_server, sizeof(sa_server));//bind sockfd and sa_server 

	CHK_ERR(err, "bind");
	err = listen(listen_sock, 5);// passive mode,request queue len is 5
	CHK_ERR(err, "listen");
	return listen_sock;
}

