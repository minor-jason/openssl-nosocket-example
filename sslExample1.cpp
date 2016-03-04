#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

static SSL_CTX* create_server() {
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_CTX* server_ctx = SSL_CTX_new(SSLv23_method());
  SSL_CTX_set_mode(server_ctx, SSL_MODE_AUTO_RETRY);
  if(server_ctx == NULL) {
    printf("ERROR Making Server Context!!!\n");
    exit(1);
  }
//  SSL_CONF_CTX *cctx = SSL_CONF_CTX_new();
//  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SERVER | SSL_CONF_FLAG_CERTIFICATE);
//  SSL_CONF_CTX_set_ssl_ctx(cctx, server_ctx);
  return server_ctx;

//  return server_ctx;
}


struct SSLClient {
  SSL* ssl;
  BIO* rio;
  BIO* wio;
};

static void printHex(const char* data, int length) {
  for(int i=0; i<length; i++) {
    printf("%X", data[i]);
  }
}
/*
static int wrap(SSLClient *engine, char *src, char *dst) {
  int write_result = 0;
  int read_result = 0;
  
  SSL_write(engine->ssl, src, strlen(src));
  
  // read_result <-- number of bytes successfully read by BIO_read from
  // engine write buffer. Written to dst. 
  read_result = BIO_read(engine->wio, dst, strlen(dst));
  return read_result;
}
*/
static int unwrap(SSLClient *engine, char *src, char *dst) {
    int read_result = 0;
    int write_result = 0;
    
    write_result = BIO_write(engine->rio, src, strlen(src));
    read_result = SSL_read(engine->ssl, dst, strlen(dst));
    
    return read_result;
}

void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile) {
  /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 ) {
      printf("Error loading certFile\n");
      exit(1);
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 ) {
      printf("Error loading keyFile\n");
      exit(1);
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) ) {
      printf("Error with Key\n");
      exit(1);
    }
}

int wrap (SSLClient *engine, char *src_buffer, char *dst_buffer) {
  char n_buff[1024];
  char a_buff[1024];

  memset(n_buff, 0, sizeof(n_buff));
  memset(a_buff, 0, sizeof(a_buff));

  int ssl_result = SSL_write(engine->ssl, src_buffer, sizeof(src_buffer));
  if(ssl_result <= 0) {
    
    if(SSL_get_error(engine->ssl, ssl_result) == SSL_ERROR_WANT_READ) {
      printf("SSL_ERROR_WANT_READ\n");
    }
    if(SSL_get_error(engine->ssl, ssl_result) == SSL_ERROR_WANT_WRITE) {
      printf("SSL_ERROR_WANT_WRITE\n");
    }

  }
  int read_result = BIO_read(engine->wio, dst_buffer, ssl_result);
  if(read_result <= 0) {
    printf("BIO_read error\n");
    return -1;
  }
  return 1;
}

int main(int argc, char* argv[]) {
  const char* file = "test.pem";
  SSLClient *c_state = new SSLClient();
  SSLClient *s_state = new SSLClient();
  SSL_load_error_strings();
  SSL_library_init();

  //Basic context for all SSL connections
  SSL_CTX* server_ctx = create_server();

  //Add Certs to connection (only required for SSL_accept)
  LoadCertificates(server_ctx, file, file);
  
  /***server********************************************************************/
  //Create an SSL stream for the server, as well as io buffers
  s_state->ssl = SSL_new(server_ctx);
  s_state->rio = BIO_new(BIO_s_mem());
  s_state->wio = BIO_new(BIO_s_mem());
  SSL_set_bio(s_state->ssl, s_state->rio, s_state->wio);

  /*****************************************************client******************/
  //Create an SSL stream for the client as well as io buffers
  c_state->ssl = SSL_new(server_ctx);
  c_state->rio = BIO_new(BIO_s_mem());
  c_state->wio = BIO_new(BIO_s_mem());
  SSL_set_bio(c_state->ssl, c_state->rio, c_state->wio);

  /***server********************************************************************/
  //Tell the Server to accept ssl negotiation.
  SSL_accept(s_state->ssl);
  
  /*****************************************************client******************/
  //Tell the Client to start negotiation.
  SSL_connect(c_state->ssl);
  
  /*****************************************************client******************/
  char cnbuff[1024]; //Client network buffer (encrypted data)  
  char cabuff[1024]; //Client app buffer (unencrypted data)
  memset(cnbuff, 0, sizeof(cnbuff));
  memset(cabuff, 0, sizeof(cabuff));    //Flush all buffers to zeros
  
  /***server********************************************************************/
  char sabuff[1024]; //Server app buffer (unencrypted data)
  char snbuff[1024]; //Server network buffer (encrypted data)
  memset(snbuff, 0, sizeof(snbuff));
  memset(sabuff, 0, sizeof(sabuff));  //Flush all buffers to zeros

  /*****Handshake*******/
/*
  int cw = BIO_read(c_state->wio, cnbuff, sizeof(cnbuff)-1);
  int sw = BIO_read(s_state->wio, snbuff, sizeof(snbuff)-1);
*/
char plaintext[] = "hello";
char ciphertext[1024];

int wrap_result = wrap(s_state, plaintext, ciphertext);
   
}
  
  
  
