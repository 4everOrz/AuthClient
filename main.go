// ccc project main.go
package main

import (
	"encoding/json"
	"fmt"
	"security"
	"strconv"
	"time"
)

/*
#cgo CFLAGS : -I./include
#cgo LDFLAGS: -L./lib  -llibeay32 -lssleay32 -lWS2_32

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>

#include <winsock2.h>

#include "openssl/rsa.h"
#include "openssl/crypto.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/rand.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")


//所有需要的参数信息都在此处以#define的形式提供
#define CERTF  "./resource/ccc.crt"  //客户端的证书(需经CA签名)
#define KEYF  "./resource/ccc.key"   //客户端的私钥(建议加密存储)
#define CACERT "./resource/ca.crt"      //CA 的证书
//#define PORT   16100          //服务端的端口
//#define SERVER_ADDR "23.99.50.231"  //服务段的IP地址   23.99.50.231

#define CHK_NULL(x) if ((x)==NULL) exit (-1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(-2); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(-3); }

int test(char *data,char *ip, int port)
{
	int err;
	int sd;
	struct sockaddr_in sa;
	SSL_CTX* ctx;
	SSL*     ssl;
	X509*    server_cert;
	char*    str;
	char     buf[4096*2];
	int       seed_int[100]; //存放随机序列

	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("WSAStartup()fail:%d/n", GetLastError());
		return -1;
	}

	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(TLSv1_2_client_method());
	CHK_NULL(ctx);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT , NULL);
	SSL_CTX_load_verify_locations(ctx, CACERT, "2");


	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-2);
	}

	SSL_CTX_set_default_passwd_cb_userdata(ctx,"jb0-43gj5(*(&698*&%$90#6^%$04-3&%*99#xyTRW770%$*&^(UIDV*^&(&^%WF");

	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-3);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		printf("Private key does not match the certificate public key/n");
		exit(-4);
	}


	srand((unsigned)time(NULL));
	for (int i = 0; i < 100; i++)
		seed_int[i] = rand();
	RAND_seed(seed_int, sizeof(seed_int));


//	printf("Begin tcp socket.../n");

	sd = socket(AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(ip);
	sa.sin_port = htons(port);

	err = connect(sd, (struct sockaddr*) &sa,
		sizeof(sa));
if (err==-1)
	{
		return 0;
	}


//	printf("Begin SSL negotiation /n");

	ssl = SSL_new(ctx);
	CHK_NULL(ssl);

	SSL_set_fd(ssl, sd);
	err = SSL_connect(ssl);



//	printf("SSL connection using %s/n", SSL_get_cipher(ssl));


	server_cert = SSL_get_peer_certificate(ssl);
	CHK_NULL(server_cert);
//	printf("Server certificate:/n");

	str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
	CHK_NULL(str);
//	printf("/t subject: %s/n", str);
	//Free(str);

	str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
	CHK_NULL(str);
//	printf("/t issuer: %s/n", str);
	//Free(str);

	X509_free(server_cert);


//	printf("Begin SSL data exchange/n");

 err = SSL_write(ssl, data, strlen(data));
	//err = SSL_write(ssl, "a",  strlen("a"));

	CHK_SSL(err);

	err = SSL_read(ssl, buf, sizeof(buf) - 1);
	CHK_SSL(err);

//	buf[err] = '/0';
//	printf("Got %d chars:'%s'/n", err, buf);
	SSL_shutdown(ssl);


	shutdown(sd, 2);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	struct sockaddr_in  connectedAddr;
	int  len = sizeof(connectedAddr);
	getpeername(sd, (struct sockaddr *)&connectedAddr,&len );
	//printf("connected server address = %s:%d\n", inet_ntoa(connectedAddr.sin_addr), ntohs(connectedAddr.sin_port));


	//system("pause");
	return 1;
}
*/
import "C"

type Pack struct {
	T    string `json:"t"`
	I    int    `json:"i"`
	Cid  string `json:"cid"`
	Tcid string `json:"tcid"`
	Pack string `json:"pack"`
}

type DevInfo struct {
	T       string `json:"t"`
	Uuid    string `json:"uuid"`
	Mac     string `json:"mac"`
	Licence string `json:"licence"`
	Ccode   string `json:"ccode"`
}

var myConfig Config
var count int
var delay int

func main() {
	myConfig = Config{}
	myConfig.InitConfig("config.ini")
	delay, _ = strconv.Atoi(myConfig.Read("default", "delay"))
	fmt.Println("客户端已启动!请求间隔:" + myConfig.Read("default", "delay") + "s")
	ticker := time.NewTicker(1 * time.Second) //15天 1296000  一周 604800  1天 86400
	for {
		select {
		case <-ticker.C:
			count++
			if count >= delay {
				test()
				count = 0
			}
		}
	} /**/
}

func test() {
	devInfo := DevInfo{T: myConfig.Read("default", "DevInfo_T"), Uuid: myConfig.Read("default", "DevInfo_Uuid"),
		Mac: myConfig.Read("default", "DevInfo_Mac"), Licence: myConfig.Read("default", "DevInfo_Licence"),
		Ccode: myConfig.Read("default", "DevInfo_Ccode")}
	//	fmt.Println(devInfo)
	data, _ := json.Marshal(devInfo)
	enData := security.AesEncrypt(data, security.GetKey(11))
	i, _ := strconv.Atoi(myConfig.Read("default", "Pack_I"))
	pack := Pack{T: myConfig.Read("default", "Pack_T"), I: i,
		Cid: myConfig.Read("default", "Pack_Cid"), Tcid: myConfig.Read("default", "Pack_Tcid"),
		Pack: string(enData)}
	//	fmt.Println(pack)
	senddata, _ := json.Marshal(pack)
	port, _ := strconv.Atoi(myConfig.Read("default", "port"))
	//	fmt.Println(string(senddata))
	if C.test(C.CString(string(senddata)), C.CString(myConfig.Read("default", "ip")), C.int(port)) == 1 {
		fmt.Println("发送成功")
	} else {
		fmt.Println("发送失败")
	}
}
