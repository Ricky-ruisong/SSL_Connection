#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>

#define MAXBUF 1024

pthread_mutex_t mutex;      //全局锁
int x = 0;                  //测试用全局变量
long Time_Stamp();          //获取时间戳函数
void *mythread();           //子线程
void ShowCerts(SSL *ssl);   //SSL加密部分
void init_sigaction();      //初始化信号
void init_time();           //设置定时器
void notify(int signum);    //终端显示变化
int HexStrToByte(const char *source, unsigned char *dest, int sourceLen);   //char to unsigned char


int main(int argc, char **argv)
{
    int sockfd, len;
    struct sockaddr_in dest;
    char buffer[MAXBUF + 1];        //设置字符串大小，多了后面的'\n'
    char *source = "Test Data";
    unsigned char *temp;
    SSL_CTX *ctx;
    SSL *ssl;
    pthread_t id;

    struct timeval time;

    if (argc != 5)
    {
        printf("参数格式错误！正确用法如下：\n\t\t%s IP地址 端口 用户数字证书路径 用户私钥路径\n\t比如:\t%s 127.0.0.1 8085 ./client.crt ./client.pem\n",argv[0], argv[0]);
        exit(0);
    }
    /* 开辟一个子线程 */
    int ret;
    ret = pthread_create(&id, NULL, &mythread, NULL);
    if (ret != 0)
    {
        printf("Create pthread error.\n");
        exit(1);
    }
    /* SSL 库初始化，参看 ssl-server.c 代码 */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    // 双向验证
    // SSL_VERIFY_PEER---要求对证书进行认证，没有证书也会放行
    // SSL_VERIFY_FAIL_IF_NO_PEER_CERT---要求服务端需要提供证书，但验证发现单独使用没有证书也会放行
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    // 设置信任根证书
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) <= 0)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    /* 载入用户的数字证书， 此证书用来发送给服务端。 证书里包含有公钥 */
    if (SSL_CTX_use_certificate_file(ctx, argv[3], SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 载入用户私钥 */
    if (SSL_CTX_use_PrivateKey_file(ctx, argv[4], SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 检查用户私钥是否正确 */
    if (!SSL_CTX_check_private_key(ctx))
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");

    /* 初始化服务器端（对方）的地址和端口信息 */
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[2]));
    if (inet_aton(argv[1], (struct in_addr *)&dest.sin_addr.s_addr) == 0)
    {
        perror(argv[1]);
        exit(errno);
    }
    printf("address created\n");

    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) != 0)
    {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n");

    /* 基于 ctx 产生一个新的 SSL */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    /* 建立 SSL 连接 */
    if (SSL_connect(ssl) == -1)
        ERR_print_errors_fp(stderr);
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }
    /*  初始化计时器  */
    init_sigaction();
    init_time();

    while (1)
    {
        bzero(buffer, MAXBUF + 1);
        int n = strlen(source) / 2;
        temp = (char *)malloc(sizeof(char) * n);
        int j = HexStrToByte(source, temp, strlen(source));
        // strcpy(buffer, temp);
        /* 发消息给服务器 */
        len = SSL_write(ssl, temp, j);
        if (len < 0)
            printf("消息'%s'发送失败！错误代码是%d，错误信息是'%s'\n",buffer, errno, strerror(errno));
        else
        {
            gettimeofday(&time, NULL);
            printf("消息'%s'发送成功，共发送了%d个字节！当前时刻%ld\n", source, len, (time.tv_sec * 1000 + time.tv_usec / 1000));
        }
        /* x部分，互斥锁保护 */
        pthread_mutex_lock(&mutex);
        printf("x in main : %d \n",x);
        printf("In pthread timestamp：%ld\n",Time_Stamp());
        pthread_mutex_unlock(&mutex);
        usleep(1000000);
        init_time();
    }
    /* 关闭连接 */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}

void ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    // SSL_get_verify_result()是重点，SSL_CTX_set_verify()只是配置启不启用并没有执行认证，调用该函数才会真证进行证书认证
    if (SSL_get_verify_result(ssl) == X509_V_OK)
    {
        printf("证书验证通过\n");
    }
    if (cert != NULL)
    {
        printf("数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        free(line);
        X509_free(cert);
    }
    // 如果验证不通过，那么程序抛出异常中止连接
    else
        printf("无证书信息！\n");
}

//十六进制字符串转换为字节流
int HexStrToByte(const char *source, unsigned char *dest, int sourceLen)
{
    short i;
    unsigned char highByte, lowByte;

    for (i = 0; i < sourceLen; i += 2)
    {
        highByte = toupper(source[i]);
        lowByte = toupper(source[i + 1]);
        if (highByte > 0x39)
            highByte -= 0x37;
        else
            highByte -= 0x30;

        if (lowByte > 0x39)
            lowByte -= 0x37;
        else
            lowByte -= 0x30;

        dest[i / 2] = (highByte << 4) | lowByte;
    }
    return i / 2;
}

long Time_Stamp() //获取时间戳
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

void init_sigaction()
{
    struct sigaction act;
    act.sa_handler = notify;
    act.sa_flags = 0;

    sigemptyset(&act.sa_mask);
    sigaction(SIGALRM, &act, NULL);
}

void init_time()
{
    struct itimerval val;
    val.it_value.tv_sec = 0;
    val.it_value.tv_usec = 600000;      //设置延迟为600ms时提醒

    val.it_interval.tv_sec = 0;
    val.it_interval.tv_usec = 600000;

    setitimer(ITIMER_REAL, &val, NULL);
}

void notify(int signum)
{
    pthread_mutex_lock(&mutex);
    printf("x in timer : %d\n",++x);
    pthread_mutex_unlock(&mutex);
    printf("In notify timestamp：%ld\n",Time_Stamp());
}

void *mythread()
{
    while(1)
    {
        pthread_mutex_lock(&mutex);
        printf("I am a pthread\n");
        printf("x in pthread : %d\n",x);
        printf("In pthread timestamp：%ld\n",Time_Stamp());
        x += 1;
        pthread_mutex_unlock(&mutex);
        sleep(3);
    }
}