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
#define CLIENT_CERTF	HOME"wxk_client.crt"
#define CLIENT_KEYF	HOME"wxk_client.key"
#define CACERT	HOME"ca.crt"

#define BUFF_SIZE 4000

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)	if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

void welcome_ui(void);
SSL * setup_tls_client(const char * hostname);
int verifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx);
int setup_tcp_client(const char *hostname,int port);
int verify_client(SSL *ssl);
int recv_virtual_ip(SSL *ssl);
int create_tun_device(int virtual_ip);

int main(int argc,char * argv[]){
    char *hostname = "wxk";   //default
    int port = 4433;    //default
    if(argc>1){
        hostname=argv[1];
    }
    if(argc>2){
        port = atoi(argv[2]);
    }
    welcome_ui();
    SSL * ssl = setup_tls_client(hostname);// tls init
    int sock_fd = setup_tcp_client(hostname,port);//tcp connection
    printf("tcp socket finish\n");
    //tls handshake
    SSL_set_fd(ssl,sock_fd);
    int err=SSL_connect(ssl);
    if(err<=0){
        fprintf(stderr,"error in SSL connect!\n");
        close(sock_fd);
        return 0;
    }
    // input user and passwd
    if(!verify_client(ssl)){
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return 0;
    }
    // get virtual_ip
    int virtual_ip = recv_virtual_ip(ssl);
    // create tun device 
    int tun_fd = create_tun_device(virtual_ip);
    // select
	char buf[BUFF_SIZE];
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
			len = read(tun_fd,buf,BUFF_SIZE);
			buf[len] = '\0';
			SSL_write(ssl,buf,len);
		}
		// client -> target
		if(FD_ISSET(sock_fd,&read_fd)){
			memset(buf,0,strlen(buf));
			len = SSL_read(ssl,buf,BUFF_SIZE);
			if(len==0){
				fprintf(stderr,"the ssl socket close!\n");
				return;
			}
			buf[len]='\0';
			write(tun_fd,buf,len);
		}
	}

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock_fd);
    return 0;
}

int create_tun_device(int virtual_ip){
    int tunfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    //IFF_TUN:表示创建一个TUN设备
    //IFF_NO_PI:表示不包含包头信息

    //打开TUN设备
    tunfd = open("/dev/net/tun", O_RDWR);
    if (tunfd == -1) {
        printf("Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    //注册设备工作模式
    int ret = ioctl(tunfd, TUNSETIFF, &ifr);
    if (ret == -1) {
        printf("Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    printf("Create a tun device :%s\n", ifr.ifr_name);
    //虚拟设备编号
    int tunId = atoi(ifr.ifr_name+3);

    char cmd[60];
    //将虚拟IP绑定到TUN设备上
    sprintf(cmd,"sudo ifconfig tun%d 192.168.53.%d/24 up",tunId, virtual_ip);
    system(cmd);
    //将发送给192.168.60.0/24的数据包交由TUN设备处理
    sprintf(cmd,"sudo route add -net 192.168.60.0/24 dev tun%d",tunId);
    system(cmd);
    return tunfd;    
}


int recv_virtual_ip(SSL *ssl){
    char buf[BUFF_SIZE];
    SSL_read(ssl,buf,BUFF_SIZE);
    int virtual_ip=atoi(buf);
    printf("virtual ip: 192.168.53.%d/24\n",virtual_ip);
    return virtual_ip;
}

int verify_client(SSL *ssl){
    char username[20];
    char passwd[20];
    char recvBuf[BUFF_SIZE];
    int len = SSL_read(ssl,recvBuf,BUFF_SIZE);   
    //username
    printf("%s\n",recvBuf);
    scanf("%s",username);
    getchar();
    SSL_write(ssl,username,strlen(username)+1);
    //passwd
    SSL_read(ssl,recvBuf,BUFF_SIZE);
    printf("%s\n",recvBuf);
    scanf("%s",passwd);
    getchar();
    SSL_write(ssl,passwd,strlen(passwd)+1);
    //check
    SSL_read(ssl,recvBuf,BUFF_SIZE);
    if(strcmp(recvBuf,"Client verify succeed")){
        printf("Client verify failed!\n");
        return 0;
    }
    printf("client verify succeed!\n");
    return 1;
}

int setup_tcp_client(const char *hostname,int port){
    struct sockaddr_in serverAddr;

    // 由域名获取IP地址
    struct hostent *hp = gethostbyname(hostname);

    // 创建TCP套接字
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(sockfd,"socket");

    // 填充服务端信息(IP, 端口号, 协议族)
    memset(&serverAddr, '\0', sizeof(serverAddr));
    memcpy(&(serverAddr.sin_addr.s_addr), hp->h_addr, hp->h_length);
    //   server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14");
    serverAddr.sin_port = htons(port);
    serverAddr.sin_family = AF_INET;

    // 与服务端建立连接
    connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    printf("TCP connect succeed! hostname IP:%s port:%d\n", inet_ntoa(serverAddr.sin_addr), port);
    return sockfd;
}

SSL * setup_tls_client(const char * hostname){
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    SSL_METHOD *meth = (SSL_METHOD *)SSLv23_client_method();
    SSL_CTX *ctx = SSL_CTX_new(meth);
    if(!ctx){
        ERR_print_errors_fp(stderr);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verifyCallback);
    if (SSL_CTX_load_verify_locations(ctx, CACERT, NULL) < 1)  {
        printf("Error setting the verify locations. \n");
        exit(0);
    }

    SSL *ssl = SSL_new(ctx);
    X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);
    SSL_CTX_free(ctx);
    return ssl;    
}


//证书验证
int verifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    char buf[300];
    X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("certificate subject= %s\n", buf);

    if (preverify_ok == 0) {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        printf("Verification failed: %s.\n",
               X509_verify_cert_error_string(err));
        return 0;   //返回0结束TLS握手连接
    }
    printf("Verification passed.\n");
    return 1;   //返回1继续TLS连接
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
