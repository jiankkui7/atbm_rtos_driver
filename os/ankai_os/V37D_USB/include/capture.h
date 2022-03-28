/*
 * lwip capture head file
 *
 */
#ifndef __LWIP_CAPTURE_H__
#define __LWIP_CAPTURE_H__

#define CAP_TX 1
#define CAP_RX 2

struct capture_filter
{
	unsigned char eth_h_dest[6];
	unsigned char eth_h_src[6];
	unsigned short eth_h_proto;
	unsigned int ip_h_dest;
	unsigned int ip_h_src;
	unsigned char ip_h_proto;
	unsigned short port_dest;
	unsigned short port_src;
	unsigned char *payload;
	unsigned int payload_len;
};

/*
*@brief application api to start capture
*@param: 
*cap_tx_rx, bit 0 - tx enable, bit 1 - rx enable
*cap_filter, capture filter, only packet match all of the filter will be captured. 
*cap_number, number of packet to capture
*cap_buf,  packet captured will be store in this buf
*time_out_second, capture timeout,
*@return:
*function will return at captured packet reach the cap_number or time_out
*it will return total len of the captured packets.
*/
int lwip_capture(int cap_tx_rx, struct capture_filter *cap_filter, int cap_number, char *cap_buf, int time_out_second);
/*
*@brief capture hook in lwip
*/
int tx_capture_hook(unsigned char *ether_p, int len);

/*
*@brief capture hook in lwip
*/
int rx_capture_hook(unsigned char *ether_p, int pkt_len);

#endif /* __LWIP_CAPTURE_H__ */
