/***************************************************************************
 *   Copyright (C) 2008 by ACREIS    *
 *   fabien.granjon@acreis.fr   *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/


#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "libmilter/mfapi.h"
#include "libmilter/mfdef.h"

#ifndef true
# define false  0
# define true  1
#endif /* ! true */



#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h> /* close */
#include <netdb.h> /* gethostbyname */
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket(s) close(s)


#define EHLO      "EHLO"
#define MAIL_FROM   "MAIL FROM:"
#define RCPT_TO   "RCPT TO:"
#define DATA    "DATA"
#define END_DATA  "."
#define QUIT    "QUIT"
#define BUF_SIZE  1024
#define CRLF    "\r\n"


//spamina code
#include "linked_list.h"
#include "eval_node.h"
#include "str_utils.h"

//incoming external
#define INCOMING 1

//outgoing external
#define OUTGOING 2

//local mail
#define LOCAL 4

//no traffic
#define NONE 0

#define LAST_MODE 4

static int traffic_types = NONE;
int (*comparator)(void *, void *) = eval;
static linked_list *domains;

int is_enabled_to_forward(char *f, char *t, linked_list *ll)
{
  int in_list_from_domain = in_list(ll,f,eval);
  int in_list_to_domain = in_list(ll,t,eval);
  int is_local_traffic = ( in_list_from_domain && in_list_to_domain );
  int is_incoming_traffic = ( ! in_list_from_domain && in_list_to_domain );
  int is_outgoing_traffic = ( in_list_from_domain && ! in_list_to_domain );

  fprintf(stdout," fromd %d to_d %d\n",in_list_from_domain,in_list_to_domain);

  if ( is_local_traffic && ( ( traffic_types & LOCAL )  == LOCAL) ) {
    fprintf(stdout,"is local\n");
    return 1;
  }
  if ( is_incoming_traffic && ( ( traffic_types & INCOMING ) == INCOMING ) ) {
    fprintf(stdout,"is incoming\n");
    return 1;
  }
  if ( is_outgoing_traffic && ( ( traffic_types & OUTGOING ) == OUTGOING ) ) {
    fprintf(stdout,"is outgoing\n");
    return 1;
  }
  return 0;
}
//end spamina code



typedef int SOCKET;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr SOCKADDR;
typedef struct in_addr IN_ADDR;



struct sockaddr_in my_asin;
struct hostent *hostinfo;
char *host;
int port=0;


struct mlfiPriv
{
  SOCKET   sock;
  int spamina_forward_enabled;
};

#define MLFIPRIV  ((struct mlfiPriv *) smfi_getpriv(ctx))

static unsigned long mta_caps = 0;


sfsistat mlfi_connect(ctx, hostname, hostaddr)
  SMFICTX *ctx;
  char *hostname;
  _SOCK_ADDR *hostaddr;
{
  char command[BUF_SIZE];
  char buffer[BUF_SIZE];

  struct mlfiPriv *priv;
  
  /* allocate some private memory */
  priv = malloc(sizeof priv);
  if (priv == NULL) {
    /* can't accept this message right now */
    return SMFIS_TEMPFAIL;
  }


  priv->sock =  socket(AF_INET, SOCK_STREAM, 0);
  priv->spamina_forward_enabled = 1 ;
  smfi_setpriv(ctx, priv);

  if(connect(priv->sock,(SOCKADDR *) &my_asin, sizeof(SOCKADDR)) == SOCKET_ERROR)
  {
    (void) fprintf(stderr, "Can't connect()");
    return SMFIS_TEMPFAIL;
  } 

  /* read response */
  read_server(priv->sock, buffer);
  return SMFIS_CONTINUE;
}

mlfi_helo(ctx, helohost)
  SMFICTX *ctx;
  char *helohost;
{
  char command[BUF_SIZE];
  char buffer[BUF_SIZE];
  struct mlfiPriv *priv = MLFIPRIV;
  
  /* send EHLO */
  sprintf(command, "%s %s%s", EHLO, helohost , CRLF);
  write_server(priv->sock, command, 0);

  /* read response */
  read_server(priv->sock, buffer);
  return SMFIS_CONTINUE;
}


sfsistat mlfi_envfrom(ctx, envfrom)
  SMFICTX *ctx;
  char **envfrom;
{
  struct mlfiPriv *priv = MLFIPRIV;
  char command[BUF_SIZE];
  char buffer[BUF_SIZE];

  char *mailaddr = smfi_getsymval(ctx, "{mail_addr}");

  /* send MAIL FROM */
  sprintf(command, "%s <%s>%s", MAIL_FROM, mailaddr, CRLF);

  write_server(priv->sock, command, 0);

  /* read response */
  read_server(priv->sock, buffer);

  /* continue processing */
  return SMFIS_CONTINUE;
}

sfsistat mlfi_envrcpt(ctx, argv)
  SMFICTX *ctx;
  char **argv;
{
  struct mlfiPriv *priv = MLFIPRIV;
  char command[BUF_SIZE];
  char buffer[BUF_SIZE];

  char *rcptaddr = smfi_getsymval(ctx, "{rcpt_addr}");
  char *fromaddr = smfi_getsymval(ctx, "{mail_addr}");
  
  char *to_domain = parse_domain(rcptaddr);
  char *from_domain = parse_domain(fromaddr);

  fprintf(stdout,"from_domain = %s to_domain = %s\n",from_domain,to_domain);
  fprintf(stdout,"flow=%d\n",traffic_types);

  priv->spamina_forward_enabled = is_enabled_to_forward ( from_domain, to_domain, domains );
  if ( priv->spamina_forward_enabled ) { 
    sprintf(command, "%s <%s>%s", RCPT_TO , rcptaddr, CRLF);
  } else {
    sprintf(command, "%s%s", QUIT, CRLF);
  }
  write_server(priv->sock, command, 0);
  read_server(priv->sock, buffer);
  free(from_domain);
  free(to_domain);
  /* continue processing */
  return SMFIS_CONTINUE;
}


sfsistat mlfi_header(ctx, headerf, headerv)
  SMFICTX *ctx;
  char *headerf;
  char *headerv;
{
  struct mlfiPriv *priv = MLFIPRIV;
  if ( ! priv->spamina_forward_enabled ) {
    return SMFIS_CONTINUE;
  }  
  char * command;
  int size=(strlen(headerf)+4+strlen(headerv))*sizeof(char);
  command=(char*)malloc((strlen(headerf)+5+strlen(headerv))*sizeof(char));
  if (!command) {
    fprintf(stderr,"Can't allocate memory");
    return SMFIS_TEMPFAIL;
  }
  
  sprintf(command, "%s: %s%s", headerf, headerv , CRLF);
  write_server(priv->sock, command, 0);
  free(command);
  return SMFIS_CONTINUE;
}



sfsistat mlfi_eoh(ctx)
  SMFICTX *ctx;
{
  /* continue processing */
  return SMFIS_CONTINUE;
}

sfsistat mlfi_body(ctx, bodyp, bodylen)
  SMFICTX *ctx;
  u_char *bodyp;
  size_t bodylen;
{
  struct mlfiPriv *priv = MLFIPRIV;
  if ( ! priv->spamina_forward_enabled ) {
    return SMFIS_CONTINUE;
  }  

  write_server(priv->sock, bodyp, bodylen );
     
  /* continue processing */
  return SMFIS_CONTINUE;
}

sfsistat mlfi_eom(ctx)
  SMFICTX *ctx;
{
  struct mlfiPriv *priv = MLFIPRIV;

  if ( ! priv->spamina_forward_enabled ) {
    return SMFIS_CONTINUE;
  }  

  char command[BUF_SIZE];
  char buffer[BUF_SIZE];

  /* send the mark of the end of the message */
  sprintf(command, "%s.%s", CRLF, CRLF);
  write_server(priv->sock, command, 0);

  /* read response */
  read_server(priv->sock, buffer);
  return SMFIS_CONTINUE;
}

sfsistat mlfi_close(ctx)
  SMFICTX *ctx;
{
  struct mlfiPriv *priv = MLFIPRIV;

  char command[BUF_SIZE];
  char buffer[BUF_SIZE];
  
  if (priv)   
    if (priv->sock != 0 && priv->spamina_forward_enabled ) {
      /* send QUIT */
      sprintf(command, "%s%s", QUIT, CRLF);
      write_server(priv->sock, command, 0);

      /* read response */
      read_server(priv->sock, buffer);
      closesocket(priv->sock );
    }

  if (priv != NULL ) {
    free(priv);
  }
  smfi_setpriv(ctx, NULL);
  return SMFIS_CONTINUE;
}

sfsistat mlfi_abort(ctx)
  SMFICTX *ctx;
{
  return SMFIS_CONTINUE;
}

sfsistat mlfi_unknown(ctx, cmd)
  SMFICTX *ctx;
  char *cmd;
{
  return SMFIS_CONTINUE;
}

sfsistat mlfi_data(ctx)
  SMFICTX *ctx;
{

  struct mlfiPriv *priv = MLFIPRIV;

  char command[BUF_SIZE];
  char buffer[BUF_SIZE];

  /* send DATA */
  sprintf(command, "%s%s", DATA, CRLF);
  write_server(priv->sock, command,0);

  /* read response */
  read_server(priv->sock, buffer);
  return SMFIS_CONTINUE;
}

sfsistat mlfi_negotiate(ctx, f0, f1, f2, f3, pf0, pf1, pf2, pf3)
  SMFICTX *ctx;
  unsigned long f0;
  unsigned long f1;
  unsigned long f2;
  unsigned long f3;
  unsigned long *pf0;
  unsigned long *pf1;
  unsigned long *pf2;
  unsigned long *pf3;
{
  /* milter protocol steps: all but connect, HELO, RCPT */
  //*pf1 = SMFIP_NOEOH | SMFIP_NOUNKNOWN;
  mta_caps = f1;
  if ((mta_caps & SMFIP_NR_HDR) != 0)
  *pf1 |= SMFIP_NR_HDR;
  *pf2 = 0;
  *pf3 = 0;
  return SMFIS_CONTINUE;
}

struct smfiDesc smfilter =
{
  "Mailforward",  /* filter name */
  SMFI_VERSION,  /* version code -- do not change */
  SMFIF_ADDHDRS,  /* flags */
  mlfi_connect ,  /* connection info filter */
  mlfi_helo,  /* SMTP HELO command filter */
  mlfi_envfrom,  /* envelope sender filter */
  mlfi_envrcpt,  /* envelope recipient filter */
  mlfi_header,  /* header filter */
  mlfi_eoh,  /* end of header */
  mlfi_body,  /* body block filter */
  mlfi_eom,  /* end of message */
  mlfi_abort ,  /* message aborted */
  mlfi_close,  /* connection cleanup */
  mlfi_unknown,  /* unknown/unimplemented SMTP commands */
  mlfi_data,  /* DATA command filter */
  mlfi_negotiate  /* option negotation at connection startup */
};

int main(argc, argv)
  int argc;
  char *argv[];
{
  bool setconn;
  int c;
  char *domain;

  setconn = false;
  domains = init_list();

  /* Process command line options */
  while ((c = getopt(argc, argv, "t:S:h:p:d:f:l:")) != -1) {
    switch (c) {
      case 'f' :
        if ( strcasecmp( optarg, "incoming" ) == 0 ) {
          traffic_types = traffic_types | INCOMING;
        }
        else
          if ( strcasecmp( optarg, "outgoing" ) == 0 ) {
            traffic_types = traffic_types | OUTGOING;
          }
          else
            if ( strcasecmp( optarg, "local" ) == 0 ) {
              traffic_types = traffic_types | LOCAL;
            }
            else {
              fprintf(stdout,"Unknown traffic type %s. Ignored\n",optarg);
            }
        break;

      case 'd':
        domain = (char *) malloc (strlen(optarg));
        if ( domain == NULL ) {
          fprintf(stderr,"Cannot allocate memory to store domain name %s",optarg);
          destroy_linked_list(domains);
          return(EX_UNAVAILABLE);
        }
        strcpy(domain,optarg);
        add_data(domain,&domains);
        break;

      case 'S':
        if (optarg == NULL || *optarg == '\0') {
          (void) fprintf(stderr, "Illegal conn: %s\n",optarg);
          exit(EX_USAGE);
        }
        (void) smfi_setconn(optarg);
        setconn = true;
        break;

      case 'h':
        if (optarg == NULL || *optarg == '\0') {
          (void) fprintf(stderr, "Illegal host: %s\n",optarg);
          exit(EX_USAGE);
        }
        host = optarg;
        break;

      case 't':
        if (optarg == NULL || *optarg == '\0') {
          (void) fprintf(stderr, "Illegal timeout: %s\n",optarg);
          exit(EX_USAGE);
        }
        if (smfi_settimeout(atoi(optarg)) == MI_FAILURE) {
          (void) fprintf(stderr,"smfi_settimeout failed\n");
          exit(EX_SOFTWARE);
        }
        break;

      case 'p':
        if (optarg == NULL || *optarg == '\0') {
          (void) fprintf(stderr, "Illegal host: %s\n",optarg);
          exit(EX_USAGE);
        }
        port  = atoi(optarg);
        break;
    }
  }
  if (!host) {
    fprintf(stderr, "%s: Missing required -h argument\n", argv[0]);
    exit(EX_USAGE);
  }
  if (!port) {
    fprintf(stderr, "%s: Missing required -p argument\n", argv[0]);
    exit(EX_USAGE);
  }
  if (!setconn) {
    fprintf(stderr, "%s: Missing required -S argument\n", argv[0]);
    exit(EX_USAGE);
  }
  if (smfi_register(smfilter) == MI_FAILURE) {
    fprintf(stderr, "smfi_register failed\n");
    exit(EX_UNAVAILABLE);
  }
  hostinfo = gethostbyname(host);
  if (hostinfo == NULL) {
    fprintf (stderr, "Unknown host %s.\n", host);
    exit(EX_UNAVAILABLE);
  }

  my_asin.sin_addr = *(IN_ADDR *) hostinfo->h_addr;
  my_asin.sin_port = htons(port);
  my_asin.sin_family = AF_INET;
  return smfi_main();
}

int read_server(SOCKET sock, char *buffer)
{
  char *p;
  int n = 0;
  if((n = recv(sock, buffer, BUF_SIZE - 1, 0)) < 0)
  {
    fprintf( stderr,"recv()");
    return 0;
  } 
  if(n == 0)
  {
     fprintf(stderr,"Connection lost\n");
     return 0;
  }
  buffer[n] = 0;
  p = strstr(buffer, CRLF);
  if(p != NULL)
  {
    *p = 0;
  }
  return 1;
}

int write_server(const SOCKET  sock, char *buffer, int length)
{
  if ( ! length ) {
    length = strlen(buffer);
  }
  if(send(sock, buffer, length, 0) < 0)
  {
    return 0;
  }
}
