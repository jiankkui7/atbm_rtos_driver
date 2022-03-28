#include "atbm_hal.h"
//#include "lwip/init.h"
#include "lwip/dhcp.h"
#include "lwip/tcpip.h"
#include "lwip/inet.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/sockets.h"
#include "lwip/icmp.h"
extern  struct netif xNetIf;
FLASH_FUNC atbm_void AT_WDisConnect(char *pLine);
FLASH_FUNC atbm_void AT_WDisConnect_vif(struct atbmwifi_vif *priv,char *pLine);
FLASH_FUNC int atbm_wifiScan();
char * CmdLine_GetToken(char ** pLine);
/*ifconfig ip 192.168.1.221  netmask 255.255.255.0 gw 192.168.1.2*/
#ifndef ATBM_COMB_IF
FLASH_FUNC static int do_ifconfig(char *pLine)
{
	struct ip_addr netmask, gw, ip_addr;
	int idx = 1;
	char * str;
	
	if (!memcmp("ip",pLine,2))
	{
		str = CmdLine_GetToken(&pLine);
		if (!memcmp("ip",str,2)) {			
			str = CmdLine_GetToken(&pLine);
			ip_addr.addr = inet_addr(str);
			netif_set_ipaddr(&xNetIf, &ip_addr);
			idx += 2;
		}
		
		str = CmdLine_GetToken(&pLine);
		if (!memcmp("netmask",str,7)) {
			str = CmdLine_GetToken(&pLine);
			netmask.addr = inet_addr(str);
			netif_set_netmask(&xNetIf, &netmask);
			idx += 2;
		}
		
		str = CmdLine_GetToken(&pLine);
		if (!memcmp("gw",str,2)) {
			str = CmdLine_GetToken(&pLine);
			gw.addr = inet_addr(str);
			netif_set_gw(&xNetIf, &gw);
			idx += 2;
		}
	}

	ATBM_DEBUG(1, 0, "ip: %s, ", inet_ntoa(*(struct in_addr*)&xNetIf.ip_addr.addr));
	ATBM_DEBUG(1, 0, "netmask: %s, ", inet_ntoa(*(struct in_addr*)&xNetIf.netmask.addr));
	ATBM_DEBUG(1, 0, "gw: %s\n", inet_ntoa(*(struct in_addr*)&xNetIf.gw.addr));

	return 0;
}
#else
/*ifconfig ifname wlan0/p2p0 ip 192.168.1.221  netmask 255.255.255.0 gw 192.168.1.2*/
extern struct atbmwifi_common g_hw_prv;
FLASH_FUNC static int do_ifconfig(char *pLine)
{
	struct ip_addr netmask, gw, ip_addr;
	int idx = 1;
	char * str;
	struct atbmwifi_common	*hw_priv = &g_hw_prv;
	struct atbmwifi_vif		*priv = ATBM_NULL;
	if (!memcmp("ifname",pLine,6))
	{
		str = CmdLine_GetToken(&pLine);
		if (!memcmp("ifname",str,6)) {			
			str = CmdLine_GetToken(&pLine);
			priv = atbmwifi_iee80211_getvif_by_name(hw_priv,str);
			if(!priv){
				wifi_printk(WIFI_ALWAYS,"check ifname ,please again\n");
			}
			idx += 6;
		}
		
		str = CmdLine_GetToken(&pLine);
		if (!memcmp("netmask",str,7)) {
			str = CmdLine_GetToken(&pLine);
			netmask.addr = inet_addr(str);
			netif_set_netmask(priv->ndev->nif, &netmask);
			idx += 2;
		}
		
		str = CmdLine_GetToken(&pLine);
		if (!memcmp("gw",str,2)) {
			str = CmdLine_GetToken(&pLine);
			gw.addr = inet_addr(str);
			netif_set_gw(priv->ndev->nif, &gw);
			idx += 2;
		}
	}

	ATBM_DEBUG(1, 0, "ip: %s, ", inet_ntoa(*(struct in_addr*)&priv->ndev->nif->ip_addr.addr));
	ATBM_DEBUG(1, 0, "netmask: %s, ", inet_ntoa(*(struct in_addr*)&priv->ndev->nif->netmask.addr));
	ATBM_DEBUG(1, 0, "gw: %s\n", inet_ntoa(*(struct in_addr*)&priv->ndev->nif->gw.addr));

	return 0;
}
#endif

#define LWIP_RAW 1

#if LWIP_RAW

#define PING_ID        0x0100
#define PING_LEN      (16)      /** ping additional data size to include in the packet */
static atbm_uint16    ping_seq_num;

static atbm_void ping_build( struct icmp_echo_hdr *iecho, atbm_uint16 len )
{
    int i;

    ICMPH_TYPE_SET( iecho, ICMP_ECHO );
    ICMPH_CODE_SET( iecho, 0 );
    iecho->chksum = 0;
    iecho->id = PING_ID;
    iecho->seqno = atbm_htons( ++ping_seq_num );

    /* fill the additional data buffer with some data */
    for ( i = 0; i < PING_LEN; i++ )
    {
        ( (char*) iecho )[sizeof(struct icmp_echo_hdr) + i] = 'a'+i;
    }

    iecho->chksum = inet_chksum((atbm_void*) iecho, len );
	
}

static err_t ping_send( int socket_s, struct ip_addr *addr )
{
    int err;
    struct icmp_echo_hdr *iecho;
    struct sockaddr_in d_addr;
    atbm_size_t ping_size = sizeof(struct icmp_echo_hdr) + PING_LEN;

    // Allocate memory for packet
    if ( ( iecho = atbm_kmalloc( ping_size ,GFP_KERNEL) ) == ATBM_NULL)
    {
    	wifi_printk(WIFI_ALWAYS,"meme alloc failed\n");
        return ERR_MEM;
    }
	
    ping_build( iecho, ping_size );

    // Send the ping request
    d_addr.sin_len = sizeof( d_addr );
    d_addr.sin_family = AF_INET;
    d_addr.sin_addr.s_addr = addr->addr;

    err = lwip_sendto( socket_s, (const atbm_void*)iecho, ping_size, 0, (struct sockaddr*) &d_addr, sizeof( d_addr ) );

    // free packet
    atbm_kfree( (atbm_void*)iecho );

    return ( err ? ERR_OK : ERR_VAL );
}

static err_t ping_recv( int socket_s )
{
    char buf[64];
    int fromlen, len;
    struct sockaddr_in from;
    struct ip_hdr *iphdr;
    struct icmp_echo_hdr *iecho;

    while ( ( len = lwip_recvfrom( socket_s, buf, sizeof( buf ), 0,
            (struct sockaddr*) &from, (socklen_t*) &fromlen ) ) > 0 )
    {
        if ( len >= (int)( sizeof(struct ip_hdr) + sizeof(struct icmp_echo_hdr) ) )
        {
            iphdr = (struct ip_hdr *) buf;
            iecho = (struct icmp_echo_hdr *) ( buf + ( IPH_HL( iphdr ) * 4 ) );

            if ( ( iecho->id == PING_ID ) &&
                 ( iecho->seqno == atbm_htons( ping_seq_num ) ) &&
                 ( ICMPH_TYPE( iecho ) == ICMP_ER ) )
            {
                return ERR_OK; // Echo reply received - return success
            }
        }
    }

    return ERR_ABRT; // No valid echo reply received before timeout
}

atbm_void do_ping(char* pLine)
{
    int socket_s = -1;
    int recv_timeout = 1000;
	int i = 0;
	atbm_uint32 send_time;
	err_t result;
	struct ip_addr ipaddr; 
	char *str;
	
	str = CmdLine_GetToken(&pLine);	
	ipaddr.addr = inet_addr(str);
			
    // Open a local socket for pinging
    if ( ( socket_s = lwip_socket( AF_INET, SOCK_RAW, IP_PROTO_ICMP ) ) < 0 )
    {
        wifi_printk(WIFI_ALWAYS,"unable to create socket for Ping\r\n");
        return;
    }

    // Set the receive timeout on local socket so pings will time out.
    lwip_setsockopt( socket_s, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof( recv_timeout ) );

    wifi_printk(WIFI_ALWAYS,"ping: %u.%u.%u.%u\r\n", 
			(unsigned char) ( ( atbm_htonl(ipaddr.addr) >> 24 ) & 0xff ),
            (unsigned char) ( ( atbm_htonl(ipaddr.addr) >> 16 ) & 0xff ),
            (unsigned char) ( ( atbm_htonl(ipaddr.addr) >> 8 ) & 0xff ),
            (unsigned char) ( ( atbm_htonl(ipaddr.addr) >> 0 ) & 0xff ));


    do {
        // Send a ping
        if ( ping_send( socket_s, (struct ip_addr*) &ipaddr.addr ) != ERR_OK )
        {
            wifi_printk(WIFI_ALWAYS,"Unable to send Ping\r\n");
            return;
        }

        // Record time ping was sent
        send_time = GetTickCount();

        // Wait for ping reply
        result = ping_recv( socket_s );
		
        // iot_printf result
        if ( ERR_OK ==  result)
        {
            wifi_printk(WIFI_ALWAYS,"ping %d reply %dms\r\n",i+1, (int)( GetTickCount()- send_time ));
        }
        else
        {
            wifi_printk(WIFI_ALWAYS,"ping timeout\r\n");
        }

        atbm_mdelay(500);
    } while (i++<10);

	
	close_socket(socket_s);

	wifi_printk(WIFI_ALWAYS,"Ping completed!\n");
}
#endif //#if LWIP_RAW


//extern mutex_t socket_mutex;
/*
 * @brief  域名解析
 *
 */
FLASH_FUNC int get_host_by_name(char *hostname, atbm_uint32 *addr)
{
	char err_t;
	struct ip_addr ip_addr;
	/**
	 * Execute a DNS query, only one IP address is returned
	 *
	 * @param name a string representation of the DNS host name to query
	 * @param addr a preallocated ip_addr_t where to store the resolved IP address
	 * @return ERR_OK: resolving succeeded
	 *         ERR_MEM: memory error, try again later
	 *         ERR_ARG: dns client not initialized or invalid hostname
	 *         ERR_VAL: dns server response was invalid
	 */
	//atbm_os_mutexLock(&socket_mutex,0);
	err_t = netconn_gethostbyname(hostname, &ip_addr);
	//atbm_os_mutexUnLock(&socket_mutex);
	if (err_t == ERR_OK)
	{
		*addr = ip_addr.addr;
		return 0;
	}

	return  - 1;
}


FLASH_FUNC int do_dns_query(char* pLine)
{
	atbm_uint32 addr;
	int ret;
	char *hostname;
	int index = 1;


	hostname = CmdLine_GetToken(&pLine);	
	if (ATBM_NULL == hostname)
	{
		wifi_printk(WIFI_ALWAYS,"input param error\r\n");
		return 0;
	}

	wifi_printk(WIFI_ALWAYS,"dns query start",hostname);

    //需要指定dns server的地址?
    //dns_setserver(atbm_uint8 numdns,struct ip_addr * dnsserver);

    ret = get_host_by_name(hostname, &addr);

	if (ret == 0)
	{
		wifi_printk(WIFI_ALWAYS,"get %s, ipaddr:: %d.%d.%d.%d\n", hostname, (addr & 0xFF), ((addr>>8) & 0xFF), ((addr>>16) & 0xFF), ((addr>>24) & 0xFF));
		return 0;

	}
	wifi_printk(WIFI_ALWAYS,"dns query end");

	return 0;
}




/*connect AP*/
extern struct atbmwifi_cfg* hmac_cfg;

extern 	int cli_process_cmd(char * Line);
#ifndef ATBM_COMB_IF
FLASH_FUNC atbm_void do_config_keymgmt(char *pLine)
{
	if (!memcmp("NONE",pLine,strlen("NONE")))
	{
		hmac_cfg.key_mgmt = ATBM_KEY_NONE;
		hmac_cfg.password_len = 0;
		hmac_cfg.auth_alg = ATBM_WLAN_AUTH_OPEN;
		hmac_cfg.privacy = 0;
	}
	else if(!memcmp("WEP",pLine,strlen("WEP")))
	{
		hmac_cfg.key_mgmt = ATBM_KEY_WEP;
		hmac_cfg.auth_alg = ATBM_WLAN_AUTH_OPEN;
		hmac_cfg.privacy = 1;
	}
	else if(!memcmp("WEP_SHARE",pLine,strlen("WEP_SHARE")))
	{
		hmac_cfg.key_mgmt = ATBM_KEY_WEP_SHARE;
		hmac_cfg.auth_alg = ATBM_WLAN_AUTH_SHARED_KEY;
		hmac_cfg.privacy = 1;
	}
	else if(!memcmp("WPA_PSK",pLine,strlen("WPA_PSK")))
	{
		hmac_cfg.key_mgmt = ATBM_KEY_WPA;
		hmac_cfg.auth_alg = ATBM_WLAN_AUTH_OPEN;
		hmac_cfg.privacy = 1;
	}
	else if(!memcmp("WPA2_PSK",pLine,strlen("WPA2_PSK")))
	{
		hmac_cfg.key_mgmt = ATBM_KEY_WPA2;
		hmac_cfg.auth_alg = ATBM_WLAN_AUTH_OPEN;
		hmac_cfg.privacy = 1;
	}
	else if(!memcmp("WPA_WPA2_PSK",pLine,strlen("WPA_WPA2_PSK")))
	{
		hmac_cfg.key_mgmt = ATBM_KEY_WPA2;
		hmac_cfg.auth_alg = ATBM_WLAN_AUTH_OPEN;
		hmac_cfg.privacy = 1;
	}
	wifi_printk(WIFI_ATCMD,"key_mgmt %s %d\n",pLine,hmac_cfg->key_mgmt);
}

FLASH_FUNC atbm_void AT_WifiConfig(char *pLine)
{
	int tmpdata = 0;
	char * str;
	
	wifi_printk(WIFI_ATCMD,"\nAT_WifiConfig\n");
	if (!memcmp("KEY_MGMT",pLine,strlen("KEY_MGMT")))
	{
		str = CmdLine_GetToken(&pLine);
		str = CmdLine_GetToken(&pLine);
		wifi_printk(WIFI_ATCMD,"KEY_MGMT %s\n",str);
		//
		do_config_keymgmt(str);
	}
	if (!memcmp("PWD",pLine,strlen("PWD")))
	{
		str = CmdLine_GetToken(&pLine);
		str = CmdLine_GetToken(&pLine);
		tmpdata = strlen(str);
		//
		switch(hmac_cfg.key_mgmt){

			case ATBM_KEY_WPA:
			case ATBM_KEY_WPA2:
				if((tmpdata<8)||(tmpdata>64)){

					p_err("keylen err!\n");
					return;
				}
				//todo add hex mode 
				break;

			case ATBM_KEY_WEP:
			case ATBM_KEY_WEP_SHARE:
				if((tmpdata!=5)||(tmpdata!=13)){

					p_err("keylen err!\n");
					return;
				}
				//todo add hex mode
				break;
			case ATBM_KEY_NONE:
			default:
				p_err("key mgmt err!\n");
				return;
				//break;

		}
		atbm_memset(hmac_cfg.password,0,sizeof(hmac_cfg->password));
		atbm_memcpy(hmac_cfg.password,str,tmpdata);
		hmac_cfg.password_len = tmpdata;
	}
	if (!memcmp("KEYID",pLine,strlen("KEYID")))
	{
		str = CmdLine_GetToken(&pLine);
		str = CmdLine_GetToken(&pLine);
		//
		CmdLine_GetInteger(&str, &tmpdata);
		wifi_printk(WIFI_ATCMD,"KEYID %d %s\n",tmpdata,str );
		//
		switch(hmac_cfg.key_mgmt){

			case ATBM_KEY_WEP:
			case ATBM_KEY_WEP_SHARE:
				if((hmac_cfg.key_id<0)||(hmac_cfg.key_id>3)){

					p_err("keyid err!\n");
					return;
				}
				hmac_cfg.key_id = tmpdata;
				break;
			case ATBM_KEY_WPA:
			case ATBM_KEY_WPA2:
			case ATBM_KEY_NONE:
			default:
				p_err("key mgmt err!\n");
				return;
				//break;

		}
	}
	if (!memcmp("SSID",pLine,strlen("SSID")))
	{
		str = CmdLine_GetToken(&pLine);
		str = CmdLine_GetToken(&pLine);
		//
		tmpdata = strlen(str);
		if((tmpdata <1)||(tmpdata > 32)){

			p_err("ssid err!\n");
			return;
		}
		atbm_memset(hmac_cfg.ssid,0,sizeof(hmac_cfg.ssid));
		atbm_memcpy(hmac_cfg.ssid,str,tmpdata);
		hmac_cfg.ssid_len = tmpdata;
		wifi_printk(WIFI_ATCMD,"ssid_len %d %s\n",hmac_cfg.ssid_len,str );
	}
	//save wifi config to flash
	//flash_param_wificonfig_change();
	//wifi_printk(WIFI_ATCMD,"AT_WifiConfig--\n");
}

FLASH_FUNC atbm_void AT_WifiModeChange(char *pLine)
{
	int tmpdata = 0;
	char * str;
	
	wifi_printk(WIFI_ATCMD,"AT_WifiModeChange\n");
	if (!memcmp("AP_MODE",pLine,strlen("AP_MODE")))
	{
			if(g_vmac->iftype==ATBM_NL80211_IFTYPE_AP){
				return ;
			}
			atbmwifi_stop_sta(g_vmac);
			atbmwifi_start_ap(g_vmac);
			g_vmac->iftype= ATBM_NL80211_IFTYPE_AP;
			///wifi_ChangeMode(1);
	}
	else if (!memcmp("STA_MODE",pLine,strlen("STA_MODE")))
	{
			if(g_vmac->iftype==ATBM_NL80211_IFTYPE_STATION){
				return ;
			}
			atbmwifi_stop_ap(g_vmac);
			atbmwifi_start_sta(g_vmac);
			g_vmac->iftype = ATBM_NL80211_IFTYPE_STATION;			
			//wifi_ChangeMode(0);					
		
	}
	else {
		wifi_printk(WIFI_ATCMD,"\nparam error! must be AP_MODE or STA_MODE\n");
	}
}
extern struct atbmwifi_common g_hw_prv;
FLASH_FUNC atbm_void AT_WifiStatus(char *Args)
{
	if(g_vmac->iftype == ATBM_NL80211_IFTYPE_AP){
		wifi_printk(WIFI_ALWAYS,"[AP mode] ");

		wifi_printk(WIFI_ALWAYS,"mac:"MACSTR"\n",MAC2STR(g_vmac->mac_addr));
		wifi_printk(WIFI_ALWAYS,"channel :%d \n",g_hw_prv.channel_idex);
	}
	else if(g_vmac->iftype == ATBM_NL80211_IFTYPE_STATION){
		wifi_printk(WIFI_ALWAYS,"[STA mode] ");

		wifi_printk(WIFI_ALWAYS,"mac:["MACSTR"] \n",MAC2STR(g_vmac->mac_addr));

		if(g_vmac->connect_ok){
			wifi_printk(WIFI_ALWAYS,"[connect]\n");
		}
		else {
			wifi_printk(WIFI_ALWAYS,"[not connect]\n");
		}
		if(g_vmac->ssid_length){
			wifi_printk(WIFI_ALWAYS,"ssid:[%s] \n",g_vmac->ssid);
		}
		else {
			wifi_printk(WIFI_ALWAYS,"ssid:[] \n");
		}
		wifi_printk(WIFI_ALWAYS,"bssid:["MACSTR"]\n",MAC2STR(g_vmac->daddr));
		wifi_printk(WIFI_ALWAYS,"channel :%d \n",g_hw_prv.channel_idex);
		//iot_printf("key_mgmt:[%s]"MACSTR"\n",MAC2STR(g_vmac->c));

	}
	else {
		wifi_printk(WIFI_ALWAYS,"WIFI MODE[%d] ERROR!!\n",g_vmac->iftype);
	}
}




/*
connect AP AT cmd
****************************************************
<type1>: "KEY_MGMT" 
			<values>: "NONE" "WEP" "WEP_SHARE" "WPA_PSK" "WPA2_PSK" "WPA_WPA2_PSK"
<type2>: "PWD" 
			<values>: "xxxxxxxxxxxx"
<type3>: "KEYID" 
			<values>: "0" "1" "2" "3" //just support for WEP or WEP_SHARE
<type4>: "SSID" 
			<values>: "xxxAP"
****************************************************
example:
1. connect open AP:
	AT+wifiCon KEY_MGMT NONE SSID wifi_test_ap15
2. connect wpa psk AP:
	AT+wifiCon KEY_MGMT WPA_WPA2_PSK PWD 1234567890 SSID wifi_test_ap15
****************************************************
*/
FLASH_FUNC atbm_void AT_WConnect(char *pLine)
{	
	int tmpdata = 0;
	char * str;
	if(!g_vmac->enabled){
		wifi_printk(WIFI_ALWAYS,"not support not enabled!\n");
		return;
	}
	if(g_vmac->iftype == ATBM_NL80211_IFTYPE_STATION){
		AT_WDisConnect(ATBM_NULL);
		AT_WifiConfig(pLine);
		wpa_connect_ap(g_vmac,hmac_cfg.ssid,hmac_cfg.ssid_len,hmac_cfg.password,hmac_cfg.password_len,hmac_cfg.key_mgmt,hmac_cfg.key_id );
		//save to flash
	}	
}

FLASH_FUNC atbm_void AT_WStopMode(char *pLine)
{
	char * str;
	struct atbmwifi_vif *priv = g_vmac;
	int tmpdata = 0;
	
	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ATCMD,"AT_WifiStartStaAndConnet:make sure IFNAME ???\n");
		return;
	}
	if(!priv->enabled){
		wifi_printk(WIFI_ALWAYS,"AT_WifiStartStaAndConnet:not support not enabled!\n");
		return;
	}

	atbm_wifi_off();
	//priv->enabled = 1;
}



#else

FLASH_FUNC atbm_void do_config_keymgmt(struct atbmwifi_vif *priv,char *pLine)
{
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);
	if (!memcmp("NONE",pLine,strlen("NONE")))
	{
		config->key_mgmt = ATBM_KEY_NONE;
		config->password_len = 0;
		config->auth_alg = ATBM_WLAN_AUTH_OPEN;
		config->privacy = 0;
	}
	else if(!memcmp("WEP",pLine,strlen("WEP")))
	{
		config->key_mgmt = ATBM_KEY_WEP;
		config->auth_alg = ATBM_WLAN_AUTH_OPEN;
		config->privacy = 1;
	}
	else if(!memcmp("WEP_SHARE",pLine,strlen("WEP_SHARE")))
	{
		config->key_mgmt = ATBM_KEY_WEP_SHARE;
		config->auth_alg = ATBM_WLAN_AUTH_SHARED_KEY;
		config->privacy = 1;
	}
	else if(!memcmp("WPA_PSK",pLine,strlen("WPA_PSK")))
	{
		config->key_mgmt = ATBM_KEY_WPA;
		config->auth_alg = ATBM_WLAN_AUTH_OPEN;
		config->privacy = 1;
	}
	else if(!memcmp("WPA2_PSK",pLine,strlen("WPA2_PSK")))
	{
		config->key_mgmt = ATBM_KEY_WPA2;
		config->auth_alg = ATBM_WLAN_AUTH_OPEN;
		config->privacy = 1;
	}
	else if(!memcmp("WPA_WPA2_PSK",pLine,strlen("WPA_WPA2_PSK")))
	{
		config->key_mgmt = ATBM_KEY_WPA2;
		config->auth_alg = ATBM_WLAN_AUTH_OPEN;
		config->privacy = 1;
	}
	wifi_printk(WIFI_ATCMD,"key_mgmt %s %d\n",pLine,config->key_mgmt);
}
FLASH_FUNC atbm_void AT_WifiConfigProcess(struct atbmwifi_vif *priv,char *pLine)
{
	struct atbmwifi_cfg *config = ATBM_NULL;
	int tmpdata = 0;
	char * str;
	config = atbmwifi_get_config(priv);
	if (!memcmp("KEY_MGMT",pLine,strlen("KEY_MGMT")))
	{
		str = CmdLine_GetToken(&pLine);
		str = CmdLine_GetToken(&pLine);
		wifi_printk(WIFI_ATCMD,"KEY_MGMT %s\n",str);
		//
		do_config_keymgmt(priv,str);
	}
	else{
		wifi_printk(WIFI_ALWAYS,"there is no KEY_MGMT,default is none\n");
		config->key_mgmt = ATBM_KEY_NONE;
		config->password_len = 0;
		config->auth_alg = WLAN_AUTH_OPEN;
		config->privacy = 0;
	}
	
	if (!memcmp("PWD",pLine,strlen("PWD")))
	{
		str = CmdLine_GetToken(&pLine);
		str = CmdLine_GetToken(&pLine);
		tmpdata = strlen(str);
		//
		if(config->key_mgmt == ATBM_KEY_NONE){
			wifi_printk(WIFI_ALWAYS,"there is no KEY_MGMT,default is none, so PWD is not usbed\n");
			goto key_id;
		}
		switch(config->key_mgmt){

			case ATBM_KEY_WPA:
			case ATBM_KEY_WPA2:
				if((tmpdata<8)||(tmpdata>64)){

					p_err("keylen err!\n");
					return;
				}
				//todo add hex mode 
				break;

			case ATBM_KEY_WEP:
			case ATBM_KEY_WEP_SHARE:
				if((tmpdata!=5)||(tmpdata!=13)){

					p_err("keylen err!\n");
					return;
				}
				//todo add hex mode
				break;
			case ATBM_KEY_NONE:
			default:
				p_err("key mgmt err!\n");
				return;
				//break;

		}
		atbm_memset(config->password,0,sizeof(config->password));
		atbm_memcpy(config->password,str,tmpdata);
		config->password_len = tmpdata;
	}
	else if(config->key_mgmt != ATBM_KEY_NONE){
		wifi_printk(WIFI_ALWAYS,"config->key_mgmt != ATBM_KEY_NONE,but no password,default is 1234567890\n");
		atbm_memset(config->password,0,sizeof(config->password));
		atbm_memcpy(config->password,"1234567890",strlen("1234567890"));
	}
key_id:
	if (!memcmp("KEYID",pLine,strlen("KEYID")))
	{
		str = CmdLine_GetToken(&pLine);
		str = CmdLine_GetToken(&pLine);
		if(config->key_mgmt == ATBM_KEY_NONE){
			wifi_printk(WIFI_ALWAYS,"there is no KEY_MGMT,default is none, so KEYID is not usbed\n");
			goto ssid;
		}
		//
		CmdLine_GetInteger(&str, &tmpdata);
		wifi_printk(WIFI_ATCMD,"KEYID %d %s\n",tmpdata,str );
		//
		switch(config->key_mgmt){

			case ATBM_KEY_WEP:
			case ATBM_KEY_WEP_SHARE:
				if((config->key_id<0)||(config->key_id>3)){

					p_err("keyid err!\n");
					return;
				}
				config->key_id = tmpdata;
				break;
			case ATBM_KEY_WPA:
			case ATBM_KEY_WPA2:
			case ATBM_KEY_NONE:
			default:
				p_err("key mgmt err!\n");
				return;
				//break;

		}
	}
ssid:
	if (!memcmp("SSID",pLine,strlen("SSID")))
	{
		str = CmdLine_GetToken(&pLine);
		str = CmdLine_GetToken(&pLine);
		//
		tmpdata = strlen(str);
		if((tmpdata <1)||(tmpdata > 32)){

			p_err("ssid err!\n");
			return;
		}
		atbm_memset(config->ssid,0,sizeof(config->ssid));
		atbm_memcpy(config->ssid,str,tmpdata);
		config->ssid_len = tmpdata;
		wifi_printk(WIFI_ATCMD,"ssid_len %d %s\n",config->ssid_len,str );
	}
	else
	{
		wifi_printk(WIFI_ALWAYS,"there is no SSID,detault is testap\n");
		atbm_memset(config->ssid,0,sizeof(config->ssid));
		atbm_memcpy(config->ssid,"testap",strlen("testap"));
		config->ssid_len = strlen("testap");
	}
	if (!memcmp("CHANNEL",pLine,strlen("CHANNEL")))
	{
		str = CmdLine_GetToken(&pLine);
		str = CmdLine_GetToken(&pLine);
		//
		CmdLine_GetInteger(&str, &tmpdata);
		config->channel_index = tmpdata;
		wifi_printk(WIFI_ATCMD,"set channel %d\n",config->channel_index);
	}
}

FLASH_FUNC atbm_void AT_WifiConfig(char *pLine)
{
	int tmpdata = 0;
	char * str;
	struct atbmwifi_vif *priv = ATBM_NULL;
	struct atbmwifi_common	*hw_priv = &g_hw_prv;
	struct atbmwifi_cfg *config = ATBM_NULL;
	wifi_printk(WIFI_ATCMD,"\nAT_WifiConfig\n");
	if(!memcmp("IFNAME",pLine,strlen("IFNAME"))){
		str = CmdLine_GetToken(&pLine);
		str = CmdLine_GetToken(&pLine);
		priv = atbmwifi_iee80211_getvif_by_name(hw_priv,str);
	}
	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ATCMD,"make sure IFNAME ???\n",str);
		return;
	}

	AT_WifiConfigProcess(priv,pLine);
	//save wifi config to flash
	//flash_param_wificonfig_change();
	//wifi_printk(WIFI_ATCMD,"AT_WifiConfig--\n");
}
FLASH_FUNC atbm_void AT_WifiModeChange(char *pLine)
{
	int tmpdata = 0;
	char * str;
	struct atbmwifi_vif *priv = ATBM_NULL;
	struct atbmwifi_common	*hw_priv = &g_hw_prv;
	if(!memcmp("IFNAME",pLine,strlen("IFNAME"))){
		str = CmdLine_GetToken(&pLine);
		str = CmdLine_GetToken(&pLine);
		priv = atbmwifi_iee80211_getvif_by_name(hw_priv,str);
	}
	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ATCMD,"\n please check IFNAME\n");
		return;
	}
	wifi_printk(WIFI_ATCMD,"AT_WifiModeChange\n");
	str = CmdLine_GetToken(&pLine);
	if (!memcmp("AP_MODE",str,strlen("AP_MODE")))
	{
			atbmwifi_start_wifimode(priv,ATBM_NL80211_IFTYPE_AP);
			priv->iftype= ATBM_NL80211_IFTYPE_AP;
			///wifi_ChangeMode(1);
	}
	else if (!memcmp("STA_MODE",str,strlen("STA_MODE")))
	{
			atbmwifi_start_wifimode(ATBM_NL80211_IFTYPE_STATION);
			priv->iftype = ATBM_NL80211_IFTYPE_STATION;			
			//wifi_ChangeMode(0);					
		
	}
	else {
		wifi_printk(WIFI_ATCMD,"\nparam error! must be AP_MODE or STA_MODE\n");
	}
}
FLASH_FUNC atbm_void AT_WifiStatus(char *Args)
{
	struct atbmwifi_vif *priv = ATBM_NULL;
	struct atbmwifi_common	*hw_priv = &g_hw_prv;
	char * str;
	if(!memcmp("IFNAME",Args,strlen("IFNAME"))){
		str = CmdLine_GetToken(&Args);
		str = CmdLine_GetToken(&Args);
		priv = atbmwifi_iee80211_getvif_by_name(hw_priv,str);
	}
	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ATCMD,"make sure IFNAME ???\n");
		return;
	}
	if(priv->iftype == ATBM_NL80211_IFTYPE_AP){
		wifi_printk(WIFI_ALWAYS,"[AP mode] ");

		wifi_printk(WIFI_ALWAYS,"mac:"MACSTR"\n",MAC2STR(priv->mac_addr));
		wifi_printk(WIFI_ALWAYS,"channel :%d \n",hw_priv->channel_idex);
	}
	else if(priv->iftype == ATBM_NL80211_IFTYPE_STATION){
		wifi_printk(WIFI_ALWAYS,"[STA mode] ");

		wifi_printk(WIFI_ALWAYS,"mac:["MACSTR"] \n",MAC2STR(priv->mac_addr));

		if(priv->connect_ok){
			wifi_printk(WIFI_ALWAYS,"[connect]\n");
		}
		else {
			wifi_printk(WIFI_ALWAYS,"[not connect]\n");
		}
		if(priv->ssid_length){
			wifi_printk(WIFI_ALWAYS,"ssid:[%s] \n",g_vmac->ssid);
		}
		else {
			wifi_printk(WIFI_ALWAYS,"ssid:[] \n");
		}
		wifi_printk(WIFI_ALWAYS,"bssid:["MACSTR"]\n",MAC2STR(priv->daddr));
		wifi_printk(WIFI_ALWAYS,"channel :%d \n",hw_priv->channel_idex);
		//iot_printf("key_mgmt:[%s]"MACSTR"\n",MAC2STR(g_vmac->c));

	}
	else {
		wifi_printk(WIFI_ALWAYS,"WIFI MODE[%d] ERROR!!\n",priv->iftype);
	}
}
FLASH_FUNC atbm_void AT_WConnectProcess(struct atbmwifi_vif *priv,char *pLine)
{
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);
	
	AT_WifiConfigProcess(priv,pLine);
	priv->iftype = ATBM_NL80211_IFTYPE_STATION;	
	wpa_connect_ap(priv,config->ssid,config->ssid_len,config->password,config->password_len,config->key_mgmt,config->key_id );
}

/*
sta starts and connect AP AT cmd
****************************************************
<type1>: "IFNAME" 
			<values>: wlan0 or p2p0
<type2>: "KEY_MGMT" 
			<values>: "NONE" "WEP" "WEP_SHARE" "WPA_PSK" "WPA2_PSK" "WPA_WPA2_PSK"
<type3>: "PWD" 
			<values>: "xxxxxxxxxxxx"
<type4>: "KEYID" 
			<values>: "0" "1" "2" "3" //just support for WEP or WEP_SHARE
<type5>: "SSID" 
			<values>: "xxxAP"
****************************************************
example:
1. connect open AP:
	AT+wifiCon KEY_MGMT NONE SSID wifi_test_ap15
2. connect wpa psk AP:
	AT+wifiCon KEY_MGMT WPA_WPA2_PSK PWD 1234567890 SSID wifi_test_ap15
****************************************************
*/

FLASH_FUNC atbm_void AT_WConnect(char *pLine)
{
	char * str;
	struct atbmwifi_vif *priv = ATBM_NULL;
	struct atbmwifi_common	*hw_priv = &g_hw_prv;
	int tmpdata = 0;
	
	if(!memcmp("IFNAME",pLine,strlen("IFNAME"))){
		str = CmdLine_GetToken(&pLine);
		str = CmdLine_GetToken(&pLine);
		priv = atbmwifi_iee80211_getvif_by_name(hw_priv,str);
	}

	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ATCMD,"AT_WifiStartStaAndConnet:make sure IFNAME ???\n");
		return;
	}
	if(!priv->enabled){
		wifi_printk(WIFI_ALWAYS,"AT_WifiStartStaAndConnet:not support not enabled!\n");
		return;
	}
	if((priv->iftype == ATBM_NL80211_IFTYPE_STATION)||(priv->iftype == ATBM_NL80211_IFTYPE_P2P_CLIENT)){
		if(priv->join_status == ATBMWIFI__JOIN_STATUS_STA)
			AT_WDisConnect_vif(priv,ATBM_NULL);
//		priv->iftype = NUM_NL80211_IFTYPES;
	}else if((priv->iftype == ATBM_NL80211_IFTYPE_AP) || (priv->iftype == ATBM_NL80211_IFTYPE_P2P_GO)){
		atbmwifi_stop_wifimode(priv,priv->iftype);
	}
	priv->enabled = 1;
	if(priv->iftype == NUM_NL80211_IFTYPES){
		atbmwifi_start_sta(priv);
	}
	AT_WConnectProcess(priv,pLine);
}

FLASH_FUNC atbm_void AT_WStartApProcess(struct atbmwifi_vif *priv,char *pLine)
{
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);
	AT_WifiConfigProcess(priv,pLine);	
	wifi_StartAP_vif(priv,config->ssid,config->ssid_len,config->password,config->password_len,config->channel_index,config->key_mgmt);
}

/*
sta starts and connect AP AT cmd
****************************************************
<type1>: "IFNAME" 
			<values>: wlan0 or p2p0
<type2>: "KEY_MGMT" 
			<values>: "NONE" "WEP" "WEP_SHARE" "WPA_PSK" "WPA2_PSK" "WPA_WPA2_PSK"
<type3>: "PWD" 
			<values>: "xxxxxxxxxxxx"
<type4>: "KEYID" 
			<values>: "0" "1" "2" "3" //just support for WEP or WEP_SHARE
<type5>: "SSID" 
			<values>: "xxxAP"
<type5>: "CHANNEL" 
			<values>: "1"......"14"
****************************************************
example:
1. open AP:
	AT+wifiStartAp KEY_MGMT NONE SSID wifi_test_ap15 CHANNEL 1
2. wpa psk AP:
	AT+wifiStartAp KEY_MGMT WPA_WPA2_PSK PWD 1234567890 SSID wifi_test_ap15 CHANNEL 1
****************************************************
*/

FLASH_FUNC atbm_void AT_WStartAp(char *pLine)
{
	char * str;
	struct atbmwifi_vif *priv = ATBM_NULL;
	struct atbmwifi_common	*hw_priv = &g_hw_prv;
	int tmpdata = 0;
	
	if(!memcmp("IFNAME",pLine,strlen("IFNAME"))){
		str = CmdLine_GetToken(&pLine);
		str = CmdLine_GetToken(&pLine);
		priv = atbmwifi_iee80211_getvif_by_name(hw_priv,str);
	}

	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ATCMD,"AT_WifiStartStaAndConnet:make sure IFNAME ???\n");
		return;
	}
	if(!priv->enabled){
		wifi_printk(WIFI_ALWAYS,"AT_WifiStartStaAndConnet:not support not enabled!\n");
		return;
	}

	atbmwifi_start_wifimode(priv,ATBM_NL80211_IFTYPE_AP);
	priv->enabled = 1;
	AT_WStartApProcess(priv,pLine);
}

FLASH_FUNC atbm_void AT_WStartStation(char *pLine)
{
	char * str;
	struct atbmwifi_vif *priv = ATBM_NULL;
	struct atbmwifi_common	*hw_priv = &g_hw_prv;
	int tmpdata = 0;
	
	if(!memcmp("IFNAME",pLine,strlen("IFNAME"))){
		str = CmdLine_GetToken(&pLine);
		str = CmdLine_GetToken(&pLine);
		priv = atbmwifi_iee80211_getvif_by_name(hw_priv,str);
	}

	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ATCMD,"AT_WifiStartStaAndConnet:make sure IFNAME ???\n");
		return;
	}
	if(!priv->enabled){
		wifi_printk(WIFI_ALWAYS,"AT_WifiStartStaAndConnet:not support not enabled!\n");
		return;
	}

	atbmwifi_start_wifimode(priv,ATBM_NL80211_IFTYPE_STATION);
	priv->enabled = 1;
}

FLASH_FUNC atbm_void AT_WStopMode(char *pLine)
{
	char * str;
	struct atbmwifi_vif *priv = ATBM_NULL;
	struct atbmwifi_common	*hw_priv = &g_hw_prv;
	int tmpdata = 0;
	
	if(!memcmp("IFNAME",pLine,strlen("IFNAME"))){
		str = CmdLine_GetToken(&pLine);
		str = CmdLine_GetToken(&pLine);
		priv = atbmwifi_iee80211_getvif_by_name(hw_priv,str);
	}

	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ATCMD,"AT_WifiStartStaAndConnet:make sure IFNAME ???\n");
		return;
	}
	if(!priv->enabled){
		wifi_printk(WIFI_ALWAYS,"AT_WifiStartStaAndConnet:not support not enabled!\n");
		return;
	}

	atbmwifi_stop_wifimode(priv,priv->iftype);
	priv->enabled = 1;
}

#endif

FLASH_FUNC atbm_void AT_WifiScanResult(char *Args)
{	
//#ifdef HMAC_STA_MODE
	int Istate;
	if(g_hw_prv.scan_ret.info ==ATBM_NULL){
		wifi_printk(WIFI_ALWAYS,"scan ATBM_NULL");
		return;
	}
	
	//Istate = OS_DisableFiqIrq();
	atbm_kfree(g_hw_prv.scan_ret.info);
	g_hw_prv.scan_ret.info = ATBM_NULL;
	g_hw_prv.scan_ret.len =0;
	//OS_RestoreFiqIrq(Istate);
//#endif //#ifdef HMAC_STA_MODE
}






/*
run in save mode
在flash 保存着两份code，
1份为savemode，
1份为平时使用的code，
用于防止客户upload 错误的code时的更新
*/
FLASH_FUNC atbm_void AT_RunSaveMode(char *Args)
{
	
}
/*保存相关参数到flash中*/
FLASH_FUNC atbm_void AT_SaveFlash(char *Args)
{
	//
}


FLASH_FUNC atbm_void AT_SmartConfigStart(char *Args)
{	
	struct smartconfig_config st_cfg = {0};
	if((g_vmac->iftype != ATBM_NL80211_IFTYPE_STATION)&&(g_vmac->iftype !=ATBM_NL80211_IFTYPE_P2P_CLIENT)) {	
		wifi_printk(WIFI_ALWAYS,"not support scan in AP mode!\n");
		return;		
	}
	if(g_hw_prv.scan.scan_smartconfig){
		wifi_printk(WIFI_ALWAYS,"scan_smartconfig now!please try later!");
		return;
   }	
	if(!g_vmac->enabled){
		wifi_printk(WIFI_ALWAYS,"not support not enabled!\n");
		return;
	}
	{
	st_cfg.type = CONFIG_TP_ATBM_SMART;
	st_cfg.magic_cnt = 1;
	st_cfg.magic_time = 70;
	st_cfg.payload_time = 12000;
	};
    smartconfig_start(&st_cfg);

}
FLASH_FUNC atbm_void AT_SmartConfigStop(char *Args)
{	
	if((g_vmac->iftype != ATBM_NL80211_IFTYPE_STATION)&&(g_vmac->iftype !=ATBM_NL80211_IFTYPE_P2P_CLIENT)) {	
		wifi_printk(WIFI_ALWAYS,"not support scan in AP mode!\n");
		return;		
	}	
	if(!g_vmac->enabled){
		wifi_printk(WIFI_ALWAYS,"not support not enabled!\n");
		return;
	}
	if(g_hw_prv.scan.scan_smartconfig){
		smartconfig_stop();
   }
}
/*添加了设置fix发送rate */
FLASH_FUNC atbm_void AT_WifiFixTxRate(char *Args)
{
	/*
	int hw_fix_rate_id =0;
    CmdLine_GetInteger(&Args, &hw_fix_rate_id);
	if((hw_fix_rate_id >=0) &&(hw_fix_rate_id < NUM_RATE_INDICES)){
		//test_iot_gpio();
		hmac_cfg->hw_fix_rate_id = hw_fix_rate_id;
		iot_printf("FixTxRate %d\n",hw_fix_rate_id);
		
	}
	else if((hw_fix_rate_id == 0xff)){		
		hmac_cfg->hw_fix_rate_id = hw_fix_rate_id;
		iot_printf("freeTxRate %d\n",hw_fix_rate_id);
	}
	else {		
		iot_printf("not support rate!\n");
	}*/
}




/*
添加了一个通过iperf -c xx.xx.xx.xx ，测试发送throughput 功能
*/
atbm_void AT_TXIperfTest(char* pLine)
{
	int socket_s = -1;
	struct sockaddr_in sockaddr;
	char *send_buf = (char *)(0x2C00000);
	char *str;
	int length = 1400;
	int sendtime = 10*HZ;/*ms*/	
	atbm_uint32 starttime = 0;

	
	str = CmdLine_GetToken(&pLine);	
	sockaddr.sin_addr.s_addr = inet_addr(str);
	
	wifi_printk(WIFI_ALWAYS,"lwip_socket %s\n",str);
	
	if((socket_s = lwip_socket(PF_INET, SOCK_STREAM, IP_PROTO_TCP)) < 0){ 
		wifi_printk(WIFI_ALWAYS,"unable to create socket for Iperf\r\n"); 
	    return; 
	}	
	
	/* connect to iperf server */
	sockaddr.sin_family      = AF_INET;
	//sockaddr.sin_addr.s_addr = inet_addr(ip); 
	sockaddr.sin_port        = atbm_htons(5001);
	//iot_printf("lwip_connect %x\n",sockaddr.sin_addr.s_addr);
	if(lwip_connect(socket_s, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0)
	{
		wifi_printk(WIFI_ALWAYS,"unable to connect to iperf server\n");
		goto done;
	}
	
	wifi_printk(WIFI_ALWAYS,"Connected to iperf server\n");
	starttime = atbm_GetOsTimeMs();
	do {
		lwip_send(socket_s, send_buf, length, 0); 
		if(((atbm_int32)atbm_GetOsTimeMs() - (atbm_int32)starttime)>sendtime){
			break;
		}
	}while(1);
	
	wifi_printk(WIFI_ALWAYS,"iperf end\n");

done:
	lwip_close(socket_s);

}

/*
添加了一个通过tftp OTA升级code的功能，步骤如下:
// fw_update1.bin   为iccm.bin,注意需要将名称修改为fw_update1.bin  
1. AT+tftp 192.168.x.x fw_update1.bin  
// fw_update2.bin   为flash.bin，注意需要将名称修改为fw_update2.bin  
2. AT+tftp 192.168.x.x fw_update2.bin
// fw_update3.bin   为任意的长度小于512的bin文件，内容不关心，注意需要将名称修改为fw_update3.bin  ，
//主要是用来触发重启系统开始更新code的操作
2. AT+tftp 192.168.x.x fw_update3.bin
*/

FLASH_FUNC atbm_void AT_Tftp(char* pLine)
{	
	char *str = CmdLine_GetToken(&pLine);	
	char *filename = CmdLine_GetToken(&pLine);	
	//Tftp_APP_Init(inet_addr(str),filename);
}
struct cli_cmd_struct{

	char *cmd;
	atbm_void (*fn)(char *args);
	struct cli_cmd_struct *next;
};



/*
static struct cli_cmd_struct ATCommands_RF[] = 
{
    {.cmd ="AT+RFTxPower",   	.fn = AT_WifiConfig, .next = (void*)0 },
	{.cmd ="AT+RFChannel",    	.fn = AT_WifiStatus, .next = (void*)0 },
	{.cmd ="AT+RFChanWith",  	.fn = AT_WConnect, .next = (void*)0 },
	{.cmd ="AT+RFShortGI",  	.fn = AT_WDisConnect, .next = (void*)0 },
	{.cmd ="AT+RFRate",			.fn = AT_WifiFixTxRate, .next = (void*)0 },
};*/
	
typedef struct CMDLINE_LOCAL_S
{
    char                Line[80];
    struct cli_cmd_struct *cmds;
}CMDLINE_LOCAL;

CMDLINE_LOCAL CmdLine = { 0 };
	//static struct cli_cmd_struct *cmds;
	



/**************************************************************************
**
** NAME        CmdLine_GetToken
**
** PARAMETERS:    *pLine -    current line location to parse.
**
** RETURNS:        the token located. It never be NULL, but can be "\0"
**              *pLine - next line location to parse.
**
** DESCRIPTION    Locate the next token from a cli.
**
**************************************************************************/
  char * CmdLine_GetToken(char ** pLine)
{
    char *    str;
    char *    line;
    char ch;
	int loop =0;
	
    line = *pLine;

    /* escape white space */
    ch = line[0];
    while(ch != 0)
    {
        /* CmdLine_GetLine() has already replaced '\n' '\r' with 0 */
        if ( (ch == ' ') || (ch == ',') || (ch == '\t') )
        {
            line++;
            ch = line[0];
			//防止AT cmd 越界
	    	loop++;
			if(loop > 1600)
				break;
			
            continue;
        }
        break;
    }

    str = line;
    while(ch != 0)
    {
        if ( (ch == ' ') || (ch == ',') || (ch == '\t') )
        {
            line[0] = 0;
            /* CmdLine_GetLine() has replaced '\n' '\r' with 0, so we can do line++ */
            line++;
            break;
        }
        line++;
        ch = line[0];
		//防止AT cmd 越界
    	loop++;
		if(loop > 1600)
			break;
    }

    *pLine = line;

    return str;
}



/**************************************************************************
**
** NAME        CmdLine_GetHex
**
** PARAMETERS:  *pLine - the current line location to parse.
**
** RETURNS:        TRUE if the next token is a hexdecimal integer.
**              *pDword - the integer returned. Unchanged if return FALSE.
**              *pLine - next line location to parse.
**
** DESCRIPTION    Read a hexdecimal integer from a cli.
**
**************************************************************************/
NORELOC FLASH_FUNC  int CmdLine_GetHex(char **pLine, atbm_uint32 *pDword)
{
    char *  str;
    char *  str0;
    int     got_hex;
    atbm_uint32  d = 0;

    str = CmdLine_GetToken(pLine);
    if (str[0] == 0)
    {
        return ATBM_FALSE;
    }

    str0 = str;
    got_hex = ATBM_FALSE;
    for (;;)
    {
        char    ch;

        ch = str[0];
        if (ch == 0)
        {
            break;
        }
        if (ch >= '0' && ch <= '9')
        {
            d = (d<<4) | (ch - '0');
        }
        else if (ch >= 'a' && ch <= 'f')
        {
            d = (d<<4) | (ch - 'a' + 10);
        }
        else if (ch >= 'A' && ch <= 'F')
        {
            d = (d<<4) | (ch - 'A' + 10);
        }
        else
        {
            got_hex = ATBM_FALSE;
            break;
        }
        got_hex = ATBM_TRUE;
        str++;
    }
    if (got_hex)
    {
        *pDword = d;
    }
    else
    {
        wifi_printk(WIFI_ALWAYS,"Invalid hexdecimal: %s\n", str0);
    }

    return got_hex;
}


/**************************************************************************
**
** NAME        CmdLine_GetInteger
**
** PARAMETERS:  *pLine - the current line location to parse.
**
** RETURNS:        TRUE if the next token is an unsigned decimal integer.
**              *pDword - the integer returned. Unchanged if return FALSE.
**              *pLine - next line location to parse.
**
** DESCRIPTION    Read an unsigned decimal integer from a cli.
**
**************************************************************************/
NORELOC  FLASH_FUNC  int CmdLine_GetInteger(char **pLine, atbm_uint32 *pDword)
{
    char *  str;
    char *  str0;
    int     got_int;
    atbm_uint32  d = 0;

    str = CmdLine_GetToken(pLine);
    if (str[0] == 0)
    {
        return ATBM_FALSE;
    }

    str0 = str;
    got_int = ATBM_FALSE;
    for (;;)
    {
        char    ch;

        ch = str[0];
        if (ch == 0)
        {
            break;
        }
        if (ch >= '0' && ch <= '9')
        {
            d = d*10 + (ch - '0');
            got_int = ATBM_TRUE;
            str++;
        }
        else
        {
            got_int = ATBM_FALSE;
            break;
        }
    }
    if (got_int)
    {
        *pDword = d;
    }
    else
    {
        wifi_printk(WIFI_ALWAYS,"Invalid unsigned decimal: %s\n", str0);
    }

    return got_int;
}

atbm_void cli_help(char *arg)
{
	struct cli_cmd_struct *cmd = CmdLine.cmds;

	wifi_printk(WIFI_ALWAYS, "\nSupported commands:\n");
	do {
		wifi_printk(WIFI_ALWAYS, "  %s\n", cmd->cmd);
		cmd = cmd->next;

	} while (cmd);

	return;
}



NORELOC FLASH_FUNC atbm_void cli_add_cmd(struct cli_cmd_struct *cmd)
{
	cmd->next = CmdLine.cmds;
	CmdLine.cmds = cmd;
}

NORELOC FLASH_FUNC atbm_void cli_add_cmds(struct cli_cmd_struct *cmds, int len)
{
	int i;

	for (i = 0; i < len; i++)
		cli_add_cmd(cmds++);
}

NORELOC FLASH_FUNC int cli_process_cmd(char * Line)
{
	struct cli_cmd_struct *p = CmdLine.cmds;
	char *		Token;

	Token = CmdLine_GetToken(&Line);

	if (Token[0] == 0)
	{
		return -1;
	}

	while (p) {

		if (atbm_memcmp(Token, p->cmd,strlen(Token))==0){
			p->fn(Line);
			return 1;
		}

		p = p->next;
	}

	wifi_printk(WIFI_ALWAYS, "Unknown cmd: %s\n", Token);
	return 0;
}
static struct cli_cmd_struct ATCommands[20] = 
{0};
atbm_void AT_TcpIpStatus(char *Args)
{	

}



atbm_uint8 cmdbuffer[1024];
extern int atcmd_readly;
static atbm_void AT_cmd_thread(atbm_void* lpParameter){

	while(1){
		if(atcmd_readly==0){
		gets(cmdbuffer);
		atcmd_readly= 1;
		}
		else {
			Sleep(100);
		}
	}

}
atbm_void atbmwifi_set_cmd(const char *descripter,int (*at_fn)(const char *argv),atbm_uint8 *index)
{
	if(*index >= 20){
		wifi_printk(WIFI_ALWAYS,"cmd buff is not enough\n");
		return;
	}
	ATCommands[*index].cmd = descripter;
	ATCommands[*index].fn = at_fn;
	*index = (*index)++;
}

atbm_void AT_WifiScan(atbm_void *arg)
{
		atbm_wifiScan(arg);
}
int  cli_main()
{
	static unsigned char atcmd_cnt=0;
	wifi_printk(WIFI_ALWAYS,"[Debug] cli_main\n");
	atbmwifi_set_cmd("AT+wifiCfg",AT_WifiConfig,&atcmd_cnt);
	atbmwifi_set_cmd("AT+wifiSt",AT_WifiStatus,&atcmd_cnt);
	atbmwifi_set_cmd("AT+wifiCon",AT_WConnect,&atcmd_cnt);
	atbmwifi_set_cmd("AT+wifiDisCon",AT_WDisConnect,&atcmd_cnt);
	atbmwifi_set_cmd("AT+wifiScan",AT_WifiScan,&atcmd_cnt);
	atbmwifi_set_cmd("AT+wifiModeChange",AT_WifiModeChange,&atcmd_cnt);
	atbmwifi_set_cmd("AT+tcpipSt",AT_TcpIpStatus,&atcmd_cnt);
	atbmwifi_set_cmd("AT+iperf",AT_TXIperfTest,&atcmd_cnt);
	atbmwifi_set_cmd("AT+ifconfig",do_ifconfig,&atcmd_cnt);
	atbmwifi_set_cmd("ping",do_ping,&atcmd_cnt);
	atbmwifi_set_cmd("dns",do_dns_query,&atcmd_cnt);
	atbmwifi_set_cmd("help",cli_help,&atcmd_cnt);
	atbmwifi_set_cmd("AT+wifiStop",AT_WStopMode,&atcmd_cnt);
	#ifdef ATBM_COMB_IF
	atbmwifi_set_cmd("AT+wifiStartAp",AT_WStartAp,&atcmd_cnt);
	atbmwifi_set_cmd("AT+wifiStartStation",AT_WStartStation,&atcmd_cnt);
	#endif
	wifi_printk(WIFI_ALWAYS,"add atcmd end(%d)\n",atcmd_cnt);
	cli_add_cmds(&ATCommands[0],atcmd_cnt);
	 CreateThread(ATBM_NULL, /* default SECURITY */
				  0,    /* default Stack size */
				  AT_cmd_thread,
				  ATBM_NULL,
				  0,    /* default creation flags */
				  ATBM_NULL  /* Thread ID is not returned * */
				);
}
