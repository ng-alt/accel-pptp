/***************************************************************************
 *   Copyright (C) 2006 by Kozlov D.   *
 *   xeb@mail.ru   *
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


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include "pppd/pppd.h"
#include "pppd/fsm.h"
#include "pppd/lcp.h"
#include "pppd/ipcp.h"
#include "pppd/ccp.h"
#include "pppd/pathnames.h"
#include "pppd/patchlevel.h"

#include "pptp_callmgr.h"

#include <stdio.h>
#include <stdlib.h>

#define PPPIOCCONNECT	_IOW('t', 58, int)	/* connect channel to unit */

extern char** environ;

char pppd_version[] = PPP_VERSION;
extern int new_style_driver;

struct pptp_conn_t
{
	__u16 call_id;
	__u16 peer_call_id;
	struct in_addr sin_addr;
	struct in_addr loc_addr;
	__u32 timeout;
	__u32 window;
};

char *pptp_server = NULL;
char *pptp_client = NULL;
char *pptp_phone = NULL;
int pptp_call_id_pair=0;
int pptp_window=10;
static int pptp_verbose;
struct in_addr localbind = { INADDR_NONE };

static int callmgr_sock;
static int pptp_fd;

//static struct in_addr get_ip_address(char *name);
static int open_callmgr(struct in_addr inetaddr, char *phonenr,int window);
static void launch_callmgr(struct in_addr inetaddr, char *phonenr,int window);
static int get_call_id(int sock, pid_t gre, pid_t pppd,
		 u_int16_t *call_id, u_int16_t *peer_call_id);

//static int pptp_devname_hook(char *cmd, char **argv, int doit);
static option_t Options[] =
{
    { "pptp_server", o_string, &pptp_server,
      "PPTP Server" },
    { "pptp_client", o_string, &pptp_client,
      "PPTP Client" },
    { "pptp_call_info",o_int, &pptp_call_id_pair,
      "PPTP call info" },
    { "pptp_phone", o_string, &pptp_phone,
      "PPTP Phone number" },
    { "pptp_window", o_int, &pptp_window,
      "PPTP sliding window size" },
    { "pptp_verbose", o_int, &pptp_verbose,
      "Be verbose about discovered access concentrators"},
    { NULL }
};

static int pptp_connect(void);
//static void pptp_send_config(int mtu,u_int32_t asyncmap,int pcomp,int accomp);
//static void pptp_recv_config(int mru,u_int32_t asyncmap,int pcomp,int accomp);
static void pptp_disconnect(void);

struct channel pptp_channel = {
    options: Options,
    //process_extra_options: &PPPOEDeviceOptions,
    check_options: NULL,
    connect: &pptp_connect,
    disconnect: &pptp_disconnect,
    establish_ppp: &generic_establish_ppp,
    disestablish_ppp: &generic_disestablish_ppp,
    //send_config: &pptp_send_config,
    //recv_config: &pptp_recv_config,
    close: NULL,
    cleanup: NULL
};

static int pptp_start_server(void)
{
	int r;
	struct pptp_conn_t conn={0,0};
	char *p;
	for(p=pptp_client;*p && *p!=':'; ++p);
	if (*p!=':')
	{
		fatal("PPTP: pptp_client option must be in format local_ip:remote_ip\n");
		return -1;
	}
	*p=0; p++;
	//struct hostent *hostinfo;

	/*hostinfo=gethostbyname(pptp_client);
  if (!hostinfo)
	{
		fatal("PPTP: Unknown host %s\n", pptp_server);
		return -1;
	}*/
	if (!inet_aton(p,&conn.sin_addr))
	{
		fatal("PPTP: invalid ip %s\n",p);
		return -1;
	}
	if (!inet_aton(pptp_client,&conn.loc_addr))
	{
		fatal("PPTP: invalid ip %s\n",pptp_client);
		return -1;
	}

	if (!pptp_call_id_pair)
	{
		fatal("PPTP: no pptp_call_info specified\n");
		return -1;
	}

	conn.call_id=htons(pptp_call_id_pair&0xffff);
	conn.peer_call_id=htons(pptp_call_id_pair>>16);
	conn.timeout=0;
	conn.window=pptp_window;

	info("PPTP: connect %s:%s call_id=%i peer_call_id=%i\n",inet_ntoa(conn.loc_addr),inet_ntoa(conn.sin_addr),conn.call_id,conn.peer_call_id);

	pptp_fd=open("/dev/pptp",O_RDWR);
	if (pptp_fd<0)
	{
		fatal("PPTP: Failed to open /dev/pptp\n");
		return -1;
	}

	r=ioctl(pptp_fd,PPPIOCCONNECT,&conn);
	if (r)
	{
		fatal("PPTP: Failed to connect (%i)\n",r);
		return -1;
	}

	return pptp_fd;
}
static int pptp_start_client(void)
{
	int r;
	struct pptp_conn_t conn={0,0};
	struct hostent *hostinfo;

	hostinfo=gethostbyname(pptp_server);
  if (!hostinfo)
	{
		fatal("PPTP: Unknown host %s\n", pptp_server);
		return -1;
	}
	conn.sin_addr=*(struct in_addr*)hostinfo->h_addr;
	{
		int sock;
		struct sockaddr_in addr;
		int len=sizeof(addr);
		addr.sin_addr=conn.sin_addr;
		addr.sin_family=AF_INET;
		addr.sin_port=htons(1700);
		sock=socket(AF_INET,SOCK_DGRAM,0);
		if (connect(sock,(struct sockaddr*)&addr,sizeof(addr)))
		{
			fatal("PPTP: connect failed\n");
			return -1;
		}
		getsockname(sock,(struct sockaddr*)&addr,&len);
		conn.loc_addr=addr.sin_addr;
		close(sock);
	}
	info("PPTP: connect server=%s\n",inet_ntoa(conn.sin_addr));
	//conn.loc_addr.s_addr=INADDR_NONE;
	conn.timeout=1;
	conn.window=pptp_window;

   do {
        /*
         * Open connection to call manager (Launch call manager if necessary.)
         */
        callmgr_sock = open_callmgr(conn.sin_addr, pptp_phone,pptp_window);
        /* Exchange PIDs, get call ID */
    } while (get_call_id(callmgr_sock, getpid(), getpid(),
               &conn.call_id, &conn.peer_call_id) < 0);

	pptp_fd=open("/dev/pptp",O_RDWR);
	if (pptp_fd<0)
	{
		fatal("Failed to open /dev/pptp\n");
		return -1;
	}
	r=ioctl(pptp_fd,PPPIOCCONNECT,&conn);
	if (r)
	{
		fatal("Failed to connect (%i)\n",r);
		return -1;
	}

	//pptp_fd=fd;
	return pptp_fd;
}
static int pptp_connect(void)
{
	if ((!pptp_server && !pptp_client) || (pptp_server && pptp_client))
	{
		fatal("PPTP: unknown mode (you must specify pptp_server or pptp_client option)");
		return -1;
	}

	if (pptp_server) return pptp_start_client();
	return pptp_start_server();
}

static void pptp_disconnect(void)
{
	close(pptp_fd);
}

static int open_callmgr(struct in_addr inetaddr, char *phonenr,int window)
{
    /* Try to open unix domain socket to call manager. */
    struct sockaddr_un where;
    const int NUM_TRIES = 3;
    int i, fd;
    pid_t pid;
    int status;
    /* Open socket */
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        fatal("Could not create unix domain socket: %s", strerror(errno));
    }
    /* Make address */
    callmgr_name_unixsock(&where, inetaddr, localbind);
    for (i = 0; i < NUM_TRIES; i++)
    {
        if (connect(fd, (struct sockaddr *) &where, sizeof(where)) < 0)
        {
            /* couldn't connect.  We'll have to launch this guy. */

            unlink (where.sun_path);

            /* fork and launch call manager process */
            switch (pid = fork())
            {
                case -1: /* failure */
                    fatal("fork() to launch call manager failed.");
                case 0: /* child */
                {
                    close (fd);
                    //close(pptp_fd);
                    /* close the pty and gre in the call manager */
                   // close(pty_fd);
                    //close(gre_fd);
                    launch_callmgr(inetaddr, phonenr,window);
                }
                default: /* parent */
                    waitpid(pid, &status, 0);
                    if (status!= 0)
                       fatal("Call manager exited with error %d", status);
                    break;
            }
            sleep(1);
        }
        else return fd;
    }
    close(fd);
    fatal("Could not launch call manager after %d tries.", i);
    return -1;   /* make gcc happy */
}

/*** call the call manager main ***********************************************/
static void launch_callmgr(struct in_addr inetaddr, char *phonenr,int window)
{
			char win[10];
      char *my_argv[7] = { "pptp", inet_ntoa(inetaddr), "--phone",phonenr,"--window",win,NULL };
      char buf[128];
      sprintf(win,"%u",window);
      snprintf(buf, sizeof(buf), "pptp: call manager for %s", my_argv[1]);
      //inststr(argc, argv, envp, buf);
      exit(callmgr_main(6, my_argv, environ));
}

/*** exchange data with the call manager  *************************************/
/* XXX need better error checking XXX */
static int get_call_id(int sock, pid_t gre, pid_t pppd,
		 u_int16_t *call_id, u_int16_t *peer_call_id)
{
    u_int16_t m_call_id, m_peer_call_id;
    /* write pid's to socket */
    /* don't bother with network byte order, because pid's are meaningless
     * outside the local host.
     */
    int rc;
    rc = write(sock, &gre, sizeof(gre));
    if (rc != sizeof(gre))
        return -1;
    rc = write(sock, &pppd, sizeof(pppd));
    if (rc != sizeof(pppd))
        return -1;
    rc = read(sock,  &m_call_id, sizeof(m_call_id));
    if (rc != sizeof(m_call_id))
        return -1;
    rc = read(sock,  &m_peer_call_id, sizeof(m_peer_call_id));
    if (rc != sizeof(m_peer_call_id))
        return -1;
    /*
     * XXX FIXME ... DO ERROR CHECKING & TIME-OUTS XXX
     * (Rhialto: I am assuming for now that timeouts are not relevant
     * here, because the read and write calls would return -1 (fail) when
     * the peer goes away during the process. We know it is (or was)
     * running because the connect() call succeeded.)
     * (James: on the other hand, if the route to the peer goes away, we
     * wouldn't get told by read() or write() for quite some time.)
     */
    *call_id = m_call_id;
    *peer_call_id = m_peer_call_id;
    return 0;
}

void plugin_init(void)
{
    if (!ppp_available() && !new_style_driver)
    {
				fatal("Linux kernel does not support PPP -- are you running 2.4.x?");
    }

    add_options(Options);

    info("PPTP plugin version %s compiled against pppd %s",
	 "0.6", PPP_VERSION);

    the_channel = &pptp_channel;
    modem = 0;
}

