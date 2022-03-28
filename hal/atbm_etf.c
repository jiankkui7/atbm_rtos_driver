/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/

#include "atbm_hal.h"
#include "atbm_etf.h"
#include "atbm_os_timer.h"

struct rxstatus{
	atbm_uint32 GainImb;
	atbm_uint32 PhaseImb;
	atbm_uint32 Cfo;
	atbm_uint32 evm;
	atbm_uint32  RSSI;
	atbm_uint32 probcnt;
};

struct rxstatus_signed{
	atbm_uint8 valid;
	atbm_int32 GainImb;
	atbm_int32 PhaseImb;
	atbm_int32 Cfo;
	atbm_int32 txevm;
	atbm_int32 evm;
	atbm_int32  RxRSSI;
	atbm_int32  TxRSSI;
	atbm_uint16 dcxo;
	atbm_int32 result;
};
static struct rxstatus_signed gRxs_s;
struct test_threshold gthreshold_param;


static atbm_uint8 CodeStart = 0;
static atbm_uint8 CodeEnd = 0;

static atbm_uint8 ucWriteEfuseFlag = 0;

int Atbm_Test_Success = 0;

int atbm_test_rx_cnt = 0;
int txevm_total = 0;
int g_ProductTestGlobal = 0;


#define DCXO_CODE_MINI		0//24//0
#define DCXO_CODE_MAX		127//38//63
#define TARGET_FREQOFFSET_HZ  (7000)
struct efuse_headr efuse_data_etf;


static atbm_uint8 ETF_bStartTx = 0;
static atbm_uint8 ETF_bStartRx = 0;
extern struct atbmwifi_vif *  g_vmac;
extern struct atbmwifi_common g_hw_prv;

extern int wsm_efuse_change_data_cmd(struct atbmwifi_common *hw_priv, const struct efuse_headr *arg,int if_id);
extern int atbm_direct_read_reg_32(struct atbmwifi_common *hw_priv, atbm_uint32 addr, atbm_uint32 *val);
extern int atbm_direct_write_reg_32(struct atbmwifi_common *hw_priv, atbm_uint32 addr, atbm_uint32 val);


int atbm_etf_test_is_start()
{
	return (ETF_bStartTx+ETF_bStartRx);
}
int atbm_etf_start_rx(int channel ,int is_40M)
{
	int ret = 0;
	char cmd[32];
	atbm_uint8 ucDbgPrintOpenFlag = 1;
	struct atbmwifi_vif *vif=g_vmac;
	struct atbmwifi_common *hw_priv;

	if(g_vmac == ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR, "g_vmac == ATBM_NULL parameters, please try again!\n");
		return -ATBM_EINVAL;
	}
	
	if(vif->iftype != ATBM_NL80211_IFTYPE_STATION){
		wifi_printk(WIFI_DBG_ERROR, "(tx)iftype is not station mode, please try again!\n");
		return -ATBM_EINVAL;
	}
	
	hw_priv=g_vmac->hw_priv;

	if(ETF_bStartTx || ETF_bStartRx){
		wifi_printk(WIFI_DBG_ERROR, "Error! already ETF_bStartRx/ETF_bStartTx, please stop first!\n");
		return 0;
	}

	//./iwpriv wlan0 fwdbg 1
    wsm_write_mib(hw_priv, WSM_MIB_ID_DBG_PRINT_TO_HOST,
						&ucDbgPrintOpenFlag, sizeof(ucDbgPrintOpenFlag), vif->if_id);

	wifi_printk(WIFI_ALWAYS, "is_40M:%d\n", is_40M);
	if((is_40M != 0) && (is_40M != 1)){
		wifi_printk(WIFI_DBG_ERROR, "invalid 40M or 20M\n");
		return -ATBM_EINVAL;
	}
	
	if(channel <= 0 || channel > 14){
		wifi_printk(WIFI_DBG_ERROR, "invalid channel!\n");
		return -ATBM_EINVAL;
	}

	if((is_40M == 1 )&& ((channel == 1)||(channel > 11))){
		wifi_printk(WIFI_DBG_ERROR, "invalid 40M rate\n");
		return -ATBM_EINVAL;
	}
	
	if (vif != ATBM_NULL)
	{
		ETF_bStartRx = 1;
		atbm_memset(cmd, 0, sizeof(32));
		sprintf(cmd,"monitor 1 %d %d ",channel ,is_40M);
		wifi_printk(WIFI_ALWAYS, "CMD:%s\n", cmd);
		ret = wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD,cmd, strlen(cmd), vif->if_id);
	}

	return ret;
}


int atbm_etf_stop_rx()
{
//	int i = 0;
	int ret = 0;
	char cmd[20] = "monitor 0 1 1 ";
	atbm_uint8 ucDbgPrintOpenFlag = 0;
	struct atbmwifi_vif *vif=g_vmac;
	struct atbmwifi_common *hw_priv;

	if(g_vmac == ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR, "g_vmac == ATBM_NULL parameters, please try again!\n");
		return -ATBM_EINVAL;
	}
	hw_priv=g_vmac->hw_priv;

	if(0 == ETF_bStartRx){
		wifi_printk(WIFI_DBG_ERROR, "please start start_rx first,then stop_rx\n");
		return -ATBM_EINVAL;
	}

	ETF_bStartRx = 0;
	
	wifi_printk(WIFI_ALWAYS, "CMD:%s\n", cmd);
	ret = wsm_write_mib(hw_priv, WSM_MIB_ID_FW_CMD,cmd, strlen(cmd), vif->if_id);

	
	//./iwpriv wlan0 fwdbg 0
    wsm_write_mib(hw_priv, WSM_MIB_ID_DBG_PRINT_TO_HOST,
						&ucDbgPrintOpenFlag, sizeof(ucDbgPrintOpenFlag), vif->if_id);
	
	return ret;
}

/*
printk("need to input parameters\n");
printk("e.g: ./iwpriv wlan0 start_tx channel,rate,len,is_40M,greedfiled\n");
printk("e.g: ./iwpriv wlan0 start_tx 1,1,300,1\n");

case 10: rate = WSM_TRANSMIT_RATE_1;
break;
case 20: rate = WSM_TRANSMIT_RATE_2;
break;
case 55: rate = WSM_TRANSMIT_RATE_5;
break;
case 110: rate = WSM_TRANSMIT_RATE_11;
break;
case 60: rate = WSM_TRANSMIT_RATE_6;
break;
case 90: rate = WSM_TRANSMIT_RATE_9;
break;
case 120: rate = WSM_TRANSMIT_RATE_12;
break;
case 180: rate = WSM_TRANSMIT_RATE_18;
break;
case 240: rate = WSM_TRANSMIT_RATE_24;
break;
case 360: rate = WSM_TRANSMIT_RATE_36;
break;
case 480: rate = WSM_TRANSMIT_RATE_48;
break;
case 540: rate = WSM_TRANSMIT_RATE_54;
break;
case 65: rate = WSM_TRANSMIT_RATE_HT_6;
break;
case 130: rate = WSM_TRANSMIT_RATE_HT_13;
break;
case 195: rate = WSM_TRANSMIT_RATE_HT_19;
break;
case 260: rate = WSM_TRANSMIT_RATE_HT_26;
break;
case 390: rate = WSM_TRANSMIT_RATE_HT_39;
break;
case 520: rate = WSM_TRANSMIT_RATE_HT_52;
break;
case 585: rate = WSM_TRANSMIT_RATE_HT_58;
break;
case 650: rate = WSM_TRANSMIT_RATE_HT_65;
*/
int atbm_etf_start_tx(int channel,int rate_value,int is_40M, int greedfiled)
{
	int ret = 0;
	struct atbmwifi_vif *vif=g_vmac;
	struct atbmwifi_common *hw_priv;
	int rate;
	
	if(g_vmac == ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR, "g_vmac == ATBM_NULL parameters, please try again!\n");
		return -ATBM_EINVAL;
	}
	
	if(vif->iftype != ATBM_NL80211_IFTYPE_STATION){
		wifi_printk(WIFI_DBG_ERROR, "(tx)iftype is not station mode, please try again!\n");
		return -ATBM_EINVAL;
	}

	hw_priv=g_vmac->hw_priv;


	if(ETF_bStartTx || ETF_bStartRx){
		wifi_printk(WIFI_DBG_ERROR, "Error! already ETF_bStartRx/ETF_bStartTx, please stop first!\n");
		return 0;
	}

	//printk("is_40M = %d\n", is_40M);
	if((is_40M != 0) && (is_40M != 1)){
			wifi_printk(WIFI_DBG_ERROR, "invalid 40M or 20M %d\n",is_40M);
			return -ATBM_EINVAL;
	}

	if((greedfiled != 0) && (greedfiled != 1)){
			wifi_printk(WIFI_DBG_ERROR, "invalid greedfiled %d\n",greedfiled);
			return -ATBM_EINVAL;
	}
	
	//check channel
	if(channel <= 0 || channel > 14){
		wifi_printk(WIFI_DBG_ERROR, "invalid channel!\n");
		return -ATBM_EINVAL;
	}

	//check rate 
	switch(rate_value){
		case 10: rate = WSM_TRANSMIT_RATE_1;
		break;
		case 20: rate = WSM_TRANSMIT_RATE_2;
		break;
		case 55: rate = WSM_TRANSMIT_RATE_5;
		break;
		case 110: rate = WSM_TRANSMIT_RATE_11;
		break;
		case 60: rate = WSM_TRANSMIT_RATE_6;
		break;
		case 90: rate = WSM_TRANSMIT_RATE_9;
		break;
		case 120: rate = WSM_TRANSMIT_RATE_12;
		break;
		case 180: rate = WSM_TRANSMIT_RATE_18;
		break;
		case 240: rate = WSM_TRANSMIT_RATE_24;
		break;
		case 360: rate = WSM_TRANSMIT_RATE_36;
		break;
		case 480: rate = WSM_TRANSMIT_RATE_48;
		break;
		case 540: rate = WSM_TRANSMIT_RATE_54;
		break;
		case 65: rate = WSM_TRANSMIT_RATE_HT_6;
		break;
		case 130: rate = WSM_TRANSMIT_RATE_HT_13;
		break;
		case 195: rate = WSM_TRANSMIT_RATE_HT_19;
		break;
		case 260: rate = WSM_TRANSMIT_RATE_HT_26;
		break;
		case 390: rate = WSM_TRANSMIT_RATE_HT_39;
		break;
		case 520: rate = WSM_TRANSMIT_RATE_HT_52;
		break;
		case 585: rate = WSM_TRANSMIT_RATE_HT_58;
		break;
		case 650: rate = WSM_TRANSMIT_RATE_HT_65;
		break;
		default:
			wifi_printk(WIFI_DBG_ERROR, "invalid rate!\n");
			return -ATBM_EINVAL;			
	}

	if((is_40M == 1 )&& (rate < WSM_TRANSMIT_RATE_HT_6)){
		wifi_printk(WIFI_DBG_ERROR, "invalid 40M rate\n");
		return -ATBM_EINVAL;
	}	
	if((is_40M == 1 )&& ((channel < 3)||(channel > 11))){
		wifi_printk(WIFI_DBG_ERROR, "invalid 40M rate,channel value range:3~11\n");
		return -ATBM_EINVAL;
	}

	if(is_40M == 1){
		is_40M = ATBM_NL80211_CHAN_HT40PLUS;//
		channel -= 2;
	}

	wifi_printk(WIFI_ALWAYS, "ATBM_NL80211_CHAN_HT40PLUS:%d\n", ATBM_NL80211_CHAN_HT40PLUS);

	//printk("%d, %d, %d, %d\n", channel, rate, len, is_40M);
	hw_priv->etf_channel = channel;
	hw_priv->etf_channel_type = is_40M;
	hw_priv->etf_rate = rate;
	hw_priv->etf_len = 1000; 
	hw_priv->etf_greedfiled = greedfiled;
	
	ETF_bStartTx = 1;
	wsm_start_tx(hw_priv, vif);
	
	return ret;
}

int atbm_etf_stop_tx()
{
	int ret = 0;
	struct atbmwifi_vif *vif=g_vmac;
	struct atbmwifi_common *hw_priv;
	
	if(g_vmac == ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR, "g_vmac == ATBM_NULL parameters, please try again!\n");
		return -ATBM_EINVAL;
	}
	hw_priv=g_vmac->hw_priv;

	if(0 == ETF_bStartTx){
		wifi_printk(WIFI_DBG_ERROR, "please start start_tx first,then stop_tx\n");
		return -ATBM_EINVAL;
	}

	wsm_stop_tx(hw_priv,vif);
	ETF_bStartTx = 0;

	return ret;
}

int atbm_etf_start_tx_single_tone(int channel,int is_40M)
{
	int ret = 0;
	struct atbmwifi_vif *vif=g_vmac;
	struct atbmwifi_common *hw_priv;
	int rate;
	
	if(g_vmac == ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR, "g_vmac == ATBM_NULL parameters, please try again!\n");
		return -ATBM_EINVAL;
	}
	hw_priv=g_vmac->hw_priv;


	if(ETF_bStartTx || ETF_bStartRx){
		wifi_printk(WIFI_DBG_ERROR, "Error! already ETF_bStartRx/ETF_bStartTx, please stop first!\n");
		return 0;
	}

	//printk("is_40M = %d\n", is_40M);
	if((is_40M != 0) && (is_40M != 1)){
		wifi_printk(WIFI_DBG_ERROR, "invalid 40M or 20M %d\n",is_40M);
		return -ATBM_EINVAL;
	}
	
	//check channel
	if(channel <= 0 || channel > 14){
		wifi_printk(WIFI_DBG_ERROR, "invalid channel!\n");
		return -ATBM_EINVAL;
	}

	rate = 4;

	if((is_40M == 1 )&& (rate < WSM_TRANSMIT_RATE_HT_6) && rate != 4){
		wifi_printk(WIFI_DBG_ERROR, "invalid 40M rate\n");
		return -ATBM_EINVAL;
	}	
	if((is_40M == 1 )&& ((channel < 3)||(channel > 11))){
		wifi_printk(WIFI_DBG_ERROR, "invalid 40M rate,channel value range:3~11\n");
		return -ATBM_EINVAL;
	}

	if(is_40M == 1){
		is_40M = ATBM_NL80211_CHAN_HT40PLUS;//
		channel -= 2;
	}

	wifi_printk(WIFI_ALWAYS, "ATBM_NL80211_CHAN_HT40PLUS:%d\n", ATBM_NL80211_CHAN_HT40PLUS);

	//printk("%d, %d, %d, %d\n", channel, rate, len, is_40M);
	hw_priv->etf_channel = channel;
	hw_priv->etf_channel_type = is_40M;
	hw_priv->etf_rate = rate;
	hw_priv->etf_len = 1000; 
	hw_priv->etf_greedfiled = 0;
	
	ETF_bStartTx = 1;
	wsm_start_tx(hw_priv, vif);
	
	return ret;
}

char * CmdLine_GetToken(char ** pLine)
 {
	 char *    str;
	 char *    line;
	 char ch;
 
	 line = *pLine;
 
	 /* escape white space */
	 ch = line[0];
	 while(ch != 0)
	 {
		 /* CmdLine_GetLine() has already replaced '\n' '\r' with 0 */
		 if ( (ch == ' ') || (ch == ',') || (ch == '\t') ||(ch == ':'))
		 {
			 line++;
			 ch = line[0];
			 continue;
		 }
		 break;
	 }
 
	 str = line;
	 while(ch != 0)
	 {
		 if ( (ch == ' ') || (ch == ',') || (ch == '\t')||(ch == ':') )
		 {
			 line[0] = 0;
			 /* CmdLine_GetLine() has replaced '\n' '\r' with 0, so we can do line++ */
			 line++;
			 break;
		 }
		 line++;
		 ch = line[0];
	 }
 
	 *pLine = line;
 
	 return str;
 }


 int CmdLine_GetHex(char **pLine, unsigned int	*pDword)
 {
	 char *  str;
	 char *  str0;
	 int	 got_hex;
	 unsigned int  d = 0;
 
	 str = CmdLine_GetToken(pLine);
	 if (str[0] == 0)
	 {
		 return 0;
	 }
 
	 str0 = str;
	 got_hex = 0;
	 for (;;)
	 {
		 char	 ch;
 
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
			 got_hex = 0;
			 break;
		 }
		 got_hex = 1;
		 str++;
	 }
	 if (got_hex)
	 {
		 *pDword = d;
	 }
	 else
	 {
		 wifi_printk(WIFI_DBG_ERROR,"Invalid hexdecimal: %s\n", str0);
	 }
 
	 return got_hex;
 }
 int CmdLine_GetSignInteger(char **pLine, int *pDword)
 {
	 char *  str;
	 char *  str0;
	 int	 got_int;
	 int negativeFlag = 0;
	 int  d = 0;
 
	 str = CmdLine_GetToken(pLine);
	 if (str[0] == 0)
	 {
		 return 0;
	 }
 
	 str0 = str;
	 got_int = 0;
	 for (;;)
	 {
		 char	 ch;
 
		 ch = str[0];
		 if (ch == 0)
		 {
			 break;
		 }
		 if((ch == '-') && (str0 == str))
		 {
			 negativeFlag = -1;
			 str++;
		 }else if (ch >= '0' && ch <= '9')
		 {
			 d = d*10 + (ch - '0');
			 got_int = 1;
			 str++;
		 }
		 else
		 {
			 got_int = 0;
			 break;
		 }
	 }
	 if (got_int)
	 {
		 if (negativeFlag < 0)
			 *pDword = d * negativeFlag;
		 else
			 *pDword = d;	 
	 }
	 else
	 {
		 wifi_printk(WIFI_DBG_ERROR,"Invalid unsigned decimal: %s\n", str0);
	 }
 
	 return got_int;
 }


 int atbm_etf_save_efuse(struct atbmwifi_common *hw_priv,struct efuse_headr *efuse_save)
 {
	 int ret = 0;
	 int iResult=0;
	 //struct atbm_vif *vif;
	 struct efuse_headr efuse_bak;
	 
	 /*
	 *LMC_STATUS_CODE__EFUSE_VERSION_CHANGE  failed because efuse version change  
	 *LMC_STATUS_CODE__EFUSE_FIRST_WRITE,		 failed because efuse by first write   
	 *LMC_STATUS_CODE__EFUSE_PARSE_FAILED,		 failed because efuse data wrong, cannot be parase
	 *LMC_STATUS_CODE__EFUSE_FULL,				 failed because efuse have be writen full
	 */
	 ret = wsm_efuse_change_data_cmd(hw_priv, efuse_save,0);
	 if (ret == LMC_STATUS_CODE__EFUSE_FIRST_WRITE)
	 {
		 wifi_printk(WIFI_DBG_ERROR,"first write\n");
		 iResult = -3;
	 }else if (ret == LMC_STATUS_CODE__EFUSE_PARSE_FAILED)
	 {
		 wifi_printk(WIFI_DBG_ERROR,"parse failed\n");
		 iResult = -4;
	 }else if (ret == LMC_STATUS_CODE__EFUSE_FULL)
	 {
		 wifi_printk(WIFI_DBG_ERROR,"efuse full\n");
		 iResult = -5;
	 }else if (ret == LMC_STATUS_CODE__EFUSE_VERSION_CHANGE)
	 {
		 wifi_printk(WIFI_DBG_ERROR,"efuse version change\n");
		 iResult = -6;
	 }else
	 {
		 iResult = 0;
	 }
	 if (iResult == 0)
	 {
		 //frame_hexdump("efuse_d", efuse_save, sizeof(struct efuse_headr));
		 memset(&efuse_bak,0,sizeof(struct efuse_headr));
		 wsm_get_efuse_data(hw_priv,(void *)&efuse_bak, sizeof(struct efuse_headr));
 
		 if(efuse_bak.specific != 0)
		 {
			 //sigmastar oid
			 efuse_save->specific = efuse_bak.specific;
		 }
		 
		 if(memcmp((void *)&efuse_bak, efuse_save, sizeof(struct efuse_headr)) !=0)
		 {
			 frame_hexdump("efuse_bak", (atbm_uint8 *)&efuse_bak, sizeof(struct efuse_headr));
			 iResult = -2;
		 }else
		 {
			 iResult = 0;
		 }
	 }
	 return iResult;
 }


 /*
**@breif:
* @cmdData: cmd + data
* @len: strlen(cmdData)
*
*/
/*
	example:
	set dcxo:dcxo value from 0 to 127
	setEfuse_dcxo,<dcxo value>

	set delta_gain:delta_gain value from 0 to 31
	setEfuse_deltagain,<delta_gain1>,<delta_gain2>,<delta_gain3>

	set mac address:mad address format 
	setEfuse_mac,00:11:22:33:44:55
*/
 int atbm_etf_set_efuse(char *cmdData, int len)
{
	int ret = -1;
	int i,cmdLen = 0;
	char *pRxData;
	int rxData;
	unsigned int rxDataUnsign;
	struct efuse_headr efuse_temp;
	struct atbmwifi_common *hw_priv = g_vmac->hw_priv;

	if(cmdData == NULL)
	{
		wifi_printk(WIFI_DBG_ERROR,"cmdData is null\n");
		return ret;
	}

	if(len < strlen("setEfuse_dcxo,0"))//len minisize
	{
		wifi_printk(WIFI_DBG_ERROR,"invalid len:%d\n", len);
		return ret;
	}
	wifi_printk(WIFI_DBG_ERROR,"len:%d,cmdData:%s\n", len, cmdData);

	cmdData[len] = 0;
	for(i=0;i<len;i++)
	{
		if(cmdData[i] == ',')
		{
			cmdLen = i;
			break;
		}
	}
	pRxData = &cmdData[cmdLen];
	wifi_printk(WIFI_DBG_ERROR,"pRxData:%s\n",pRxData);

	memset(&efuse_temp, 0, sizeof(struct efuse_headr));
	if(wsm_get_efuse_data(hw_priv,(void *)&efuse_temp,sizeof(struct efuse_headr)) != 0)
	{
		wifi_printk(WIFI_DBG_ERROR,"get efuse failed\n");
		return ret;
	}	

	if(memcmp(cmdData, "setEfuse_dcxo", 13) == 0)
	{
		CmdLine_GetSignInteger(&pRxData, &rxData);
		efuse_temp.dcxo_trim = rxData;
		wifi_printk(WIFI_DBG_ERROR,"set efuse data is dcxo[%d]\n",efuse_temp.dcxo_trim);
	}
	else if(memcmp(cmdData, "setEfuse_deltagain", 18) == 0)
	{
		CmdLine_GetSignInteger(&pRxData, &rxData);
		efuse_temp.delta_gain1 = rxData;
		//atbm_printk_err("%s %d\n", __func__, __LINE__);
		CmdLine_GetSignInteger(&pRxData, &rxData);
		efuse_temp.delta_gain2 = rxData;
		//atbm_printk_err("%s %d\n", __func__, __LINE__);
		CmdLine_GetSignInteger(&pRxData, &rxData);
		efuse_temp.delta_gain3 = rxData;
		
		wifi_printk(WIFI_DBG_ERROR,"set efuse data is delta_gain[%d,%d,%d]\n",
			efuse_temp.delta_gain1,efuse_temp.delta_gain2,efuse_temp.delta_gain3);
	}
	else if(memcmp(cmdData, "setEfuse_mac", 12) == 0)
	{
		CmdLine_GetHex(&pRxData, &rxDataUnsign);
		efuse_temp.mac[0] = rxDataUnsign;
		//atbm_printk_err("%s %d\n", __func__, __LINE__);
		CmdLine_GetHex(&pRxData, &rxDataUnsign);
		efuse_temp.mac[1] = rxDataUnsign;
		//atbm_printk_err("%s %d\n", __func__, __LINE__);
		CmdLine_GetHex(&pRxData, &rxDataUnsign);
		efuse_temp.mac[2] = rxDataUnsign;
		//atbm_printk_err("%s %d\n", __func__, __LINE__);
		CmdLine_GetHex(&pRxData, &rxDataUnsign);
		efuse_temp.mac[3] = rxDataUnsign;
		//atbm_printk_err("%s %d\n", __func__, __LINE__);
		CmdLine_GetHex(&pRxData, &rxDataUnsign);
		efuse_temp.mac[4] = rxDataUnsign;
		//atbm_printk_err("%s %d\n", __func__, __LINE__);
		CmdLine_GetHex(&pRxData, &rxDataUnsign);
		efuse_temp.mac[5] = rxDataUnsign;
		wifi_printk(WIFI_DBG_ERROR,"set efuse data is mac[%02x:%02x:%02x:%02x:%02x:%02x]\n",
					efuse_temp.mac[0],efuse_temp.mac[1],efuse_temp.mac[2],
					efuse_temp.mac[3],efuse_temp.mac[4],efuse_temp.mac[5]);
	}


	ret = atbm_etf_save_efuse(hw_priv, &efuse_temp);
	if (ret == 0)
	{
		wifi_printk(WIFI_DBG_ERROR,"setEfuse success \n");
	}else
	{
		wifi_printk(WIFI_DBG_ERROR,"setEfuse failed [%d]\n", ret);
	}

	return ret;
}
/*
**@breif:get efuse
* @extra: buff save efuse data
* @len: size of buff
*/
 int atbm_etf_get_efuse(char *extra, int len)
{
	int ret = -1;
	struct efuse_headr efuse_temp;
	struct atbmwifi_common *hw_priv = g_vmac->hw_priv;

	if(extra == NULL)
	{
		wifi_printk(WIFI_DBG_ERROR,"cmdData is null\n");
		return ret;
	}

	if(len < 128)//buffer size
	{
		wifi_printk(WIFI_DBG_ERROR,"invalid len:%d\n",len);
		return ret;
	}

	memset(&efuse_temp, 0, sizeof(struct efuse_headr));
	if(wsm_get_efuse_data(hw_priv,(void *)&efuse_temp,sizeof(struct efuse_headr)) == 0)
	{
		sprintf(extra, "[%d,%d,%d,%d,%d,%d,%d,%d,%02x:%02x:%02x:%02x:%02x:%02x]",efuse_temp.version,efuse_temp.dcxo_trim,
			efuse_temp.delta_gain1,efuse_temp.delta_gain2,efuse_temp.delta_gain3,
			efuse_temp.Tj_room,efuse_temp.topref_ctrl_bias_res_trim,efuse_temp.PowerSupplySel,
			efuse_temp.mac[0],efuse_temp.mac[1],efuse_temp.mac[2],
			efuse_temp.mac[3],efuse_temp.mac[4],efuse_temp.mac[5]);
		wifi_printk(WIFI_ALWAYS,"efuse data is %s\n", extra);
		ret = 0;
	}
	else
	{
		wifi_printk(WIFI_DBG_ERROR,"get efuse failed\n");
		ret = -2;
	}

	return ret;
}

atbm_uint32 MyRand(void)
{
	atbm_uint32 random_num = 0;
	atbm_uint32 randseed = 0;

	randseed = atbm_GetOsTimeMs();
	random_num = randseed * 1103515245 + 12345;
	return ((random_num/65536)%32768);
}


int atbm_etf_PT_Test_start(/*atbm_int32 targetFreq, atbm_int32 rssiFilter, atbm_int32 evmFilter, atbm_int32 cableLoss, */atbm_int32 isWriteEfuse)
{
	struct atbmwifi_vif *vif=g_vmac;
	struct atbmwifi_common *hw_priv;

	if(g_vmac == ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR, "g_vmac == ATBM_NULL parameters, please try again!\n");
		return -ATBM_EINVAL;
	}
	
	if(vif->iftype != ATBM_NL80211_IFTYPE_STATION){
		wifi_printk(WIFI_DBG_ERROR, "(tx)iftype is not station mode, please try again!\n");
		return -ATBM_EINVAL;
	}

	hw_priv = g_vmac->hw_priv;

	atbm_memset(&gRxs_s, 0, sizeof(struct rxstatus_signed));
	atbm_memset(&gthreshold_param, 0, sizeof(struct test_threshold));

	hw_priv->etf_channel = 7;
	hw_priv->etf_channel_type = 0;
	hw_priv->etf_rate = WSM_TRANSMIT_RATE_HT_65;
	hw_priv->etf_len = 1000; 
	hw_priv->etf_greedfiled = 0;
	hw_priv->scan.in_progress = 0;
#if 0
	if(targetFreq <= 0)
	{
		wifi_printk(WIFI_DBG_ERROR, "[ERROR]:Invalid Target Freq,targetFreq:%d\n", targetFreq);
		return -1;
	}

	if(rssiFilter <= 0)
	{
		wifi_printk(WIFI_DBG_ERROR, "[ERROR]:Invalid Rssi Filter,rssiFilter:%d\n", rssiFilter);
		return -1;
	}

	if(evmFilter <= 0)
	{
		wifi_printk(WIFI_DBG_ERROR, "[ERROR]:Invalid EVM Filter,evmFilter:%d\n", evmFilter);
		return -1;
	}

	if(cableLoss <= 0)
	{
		wifi_printk(WIFI_DBG_ERROR, "[ERROR]:Invalid CableLoss,cableLoss:%d\n", cableLoss);
		return -1;
	}

	if((isWriteEfuse < 0) || (isWriteEfuse > 1))
	{
		wifi_printk(WIFI_DBG_ERROR, "[ERROR]:Invalid Efuse Flag,isWriteEfuse:%d\n", isWriteEfuse);
		return -1;
	}
#endif
	ucWriteEfuseFlag = isWriteEfuse;

	gthreshold_param.featureid = MyRand();
	gthreshold_param.freq_ppm = TARGET_FREQOFFSET_HZ;
	gthreshold_param.rssifilter = -100;
	gthreshold_param.rxevm = 400;
	gthreshold_param.txevm = 400;
	gthreshold_param.txevmthreshold = 400;
	gthreshold_param.rxevmthreshold = 400;
	gthreshold_param.cableloss = 30*4;

	wifi_printk(WIFI_DBG_ERROR, "featureid:%d\n", gthreshold_param.featureid);
	wifi_printk(WIFI_DBG_ERROR, "Freq:%d,txEvm:%d,rxEvm:%d,txevmthreshold:%d,rxevmthreshold:%d,Txpwrmax:%d,Txpwrmin:%d,Rxpwrmax:%d,Rxpwrmin:%d,rssifilter:%d,cableloss:%d\n",
		gthreshold_param.freq_ppm,gthreshold_param.txevm,gthreshold_param.rxevm,gthreshold_param.txevmthreshold,gthreshold_param.rxevmthreshold,
		gthreshold_param.txpwrmax,gthreshold_param.txpwrmin,gthreshold_param.rxpwrmax,
		gthreshold_param.rxpwrmin,gthreshold_param.rssifilter,gthreshold_param.cableloss);

	if(ETF_bStartTx || ETF_bStartRx){
		wifi_printk(WIFI_DBG_ERROR, "Error! already ETF_bStartRx/ETF_bStartTx, please stop first!\n");
		return 0;
	}
	
	g_ProductTestGlobal = 1; //product test flag

	CodeStart = DCXO_CODE_MINI;
	CodeEnd = DCXO_CODE_MAX;
	atbm_test_rx_cnt = 0;
	
	ETF_bStartTx = 1;
	wsm_start_tx_v2(hw_priv,vif);
	return 0;
}

int atbm_etf_PT_Test_result_get()
{
	int len = 0;
	char buff[512];

	memset(buff, 0, 512);

	len = sprintf(buff, "%dcfo:%d,txevm:%d,rxevm:%d,dcxo:%d,txrssi:%d,rxrssi:%d,result:%d (0:OK; -1:FreqOffset Error; -2:efuse hard error;"
		" -3:efuse no written; -4:efuse anaysis failed; -5:efuse full; -6:efuse version change; -7:rx null)",
	gRxs_s.valid,
	gRxs_s.Cfo,
	gRxs_s.txevm,
	gRxs_s.evm,
	gRxs_s.dcxo,
	gRxs_s.TxRSSI,
	gRxs_s.RxRSSI,
	gRxs_s.result
	);

	wifi_printk(WIFI_DBG_MSG, "%s\n", buff);

	return len;
}


int DCXOCodeWrite(struct atbmwifi_common *hw_priv,atbm_uint8 data)
{
	atbm_uint32 uiRegData;

	atbm_direct_read_reg_32(hw_priv, DCXO_TRIM_REG, &uiRegData);
	//hw_priv->sbus_ops->sbus_read_sync(hw_priv->sbus_priv,DCXO_TRIM_REG,&uiRegData,4);
	uiRegData &= ~0x40003F;

	uiRegData |= (((data&0x40)<<16)|(data&0x3f));
	atbm_direct_write_reg_32(hw_priv, DCXO_TRIM_REG, uiRegData);
	//hw_priv->sbus_ops->sbus_write_sync(hw_priv->sbus_priv,DCXO_TRIM_REG,&uiRegData,4);

	return 0;
}

atbm_uint8 DCXOCodeRead(struct atbmwifi_common *hw_priv)
{	
	atbm_uint32 uiRegData;
	atbm_uint8 dcxo;
	atbm_uint8 dcxo_hi,dcxo_low;

	atbm_direct_read_reg_32(hw_priv, DCXO_TRIM_REG, &uiRegData);
	//hw_priv->sbus_ops->sbus_read_sync(hw_priv->sbus_priv,DCXO_TRIM_REG,&uiRegData,4);	
	dcxo_hi = (uiRegData>>22)&0x01;
	dcxo_low = uiRegData&0x3f;
	dcxo = (dcxo_hi << 6) + (dcxo_low&0x3f);
	
	return dcxo;
}

#define N_BIT_TO_SIGNED_32BIT(v,n)	(atbm_int32)(((v) & BIT(n-1))?((v)|0xffffffff<<n):(v))



void etf_rx_status_get(struct atbmwifi_common *hw_priv)
{
	int i = 0;
	struct rxstatus rxs; 
	char *extra = NULL;
	struct atbmwifi_vif *vif;
	
	if(!(extra = atbm_kmalloc(sizeof(struct rxstatus), GFP_KERNEL)))
		return;

	atbm_for_each_vif(hw_priv,vif,i){
		if (vif != NULL)
		{
			/*WARN_ON*/(wsm_read_mib(hw_priv, WSM_MIB_ID_GET_ETF_RX_STATS,
				extra, sizeof(struct rxstatus), vif->if_id));
			break;
		}
	}
	memcpy(&rxs, extra, sizeof(struct rxstatus));
	
	atbm_kfree(extra);

	if(rxs.probcnt == 0)
		return;
	
	gRxs_s.evm				= rxs.evm/rxs.probcnt;
	gRxs_s.RxRSSI			= (atbm_int16)N_BIT_TO_SIGNED_32BIT(rxs.RSSI, 8)*4;
	gRxs_s.RxRSSI += gthreshold_param.cableloss;

	return;

}

int Test_FreqOffset_v2(struct atbmwifi_common *hw_priv, atbm_uint32 *dcxo, int *pfreqErrorHz)
{
	atbm_uint8 CodeValue,CodeValuebak;
	int b_fail =1;
	int freqErrorHz = 0;
	int targetFreqOffset = TARGET_FREQOFFSET_HZ;

	//if(gthreshold_param.freq_ppm != 0)
		//targetFreqOffset = gthreshold_param.freq_ppm;
		
	CodeValue = DCXOCodeRead(hw_priv);	
	DCXOCodeWrite(hw_priv,CodeValue);	


	wifi_printk(WIFI_DBG_ERROR,"CodeValue default:%d\n",CodeValue);

	
	CodeValuebak = CodeValue;

	freqErrorHz = gRxs_s.Cfo;

	if (freqErrorHz > targetFreqOffset)
	{
		CodeStart = CodeValue;
		CodeValue += (CodeEnd - CodeStart)/2;
		CodeStart = CodeValuebak;

		wifi_printk(WIFI_DBG_ERROR, "freqErrorHz[%d] > targetFreqOffset[%d],CodeValue[%d] ,CodeStart[%d], CodeEnd[%d] . \n",
			freqErrorHz,targetFreqOffset,	CodeValue, CodeStart ,CodeEnd );
		
		DCXOCodeWrite(hw_priv,CodeValue);

		b_fail = 1;
		if (CodeValue >= 126)
		{
			b_fail = 2;
		}
		if (CodeValue >= 0xff)
		{
			b_fail = 2;
		}
	}
	else if ((int)freqErrorHz < -targetFreqOffset)
	{
		CodeEnd = CodeValue;
		CodeValue -= (CodeEnd - CodeStart)/2;
		CodeEnd = CodeValuebak;

		wifi_printk(WIFI_DBG_ERROR, "freqErrorHz[%d] < targetFreqOffset[%d],CodeValue[%d] ,CodeStart[%d], CodeEnd[%d] . \n",
			freqErrorHz,targetFreqOffset,	CodeValue, CodeStart ,CodeEnd );
		DCXOCodeWrite(hw_priv,CodeValue);

		b_fail = 1;
		
		if (CodeValue <= 2)
		{
			b_fail = 3;
		}
		if (0x01 == CodeEnd)
		{
			b_fail = 3;
		}
	}
	else
	{
		wifi_printk(WIFI_DBG_ERROR, "[dcxo PASS]freqErrorKHz[%d] CodeValue[%d]!\n",freqErrorHz/1000,CodeValue);
		b_fail = 0;
		*dcxo = CodeValue;
		*pfreqErrorHz = freqErrorHz;
	}

	
	return b_fail;

}

static int atbm_freqoffset_save_efuse(struct atbmwifi_common *hw_priv,struct rxstatus_signed rxs_s,atbm_uint32 dcxo)
{
	int ret = 0;
	int iResult=0;
	//struct atbm_vif *vif;
	struct efuse_headr efuse_d,efuse_bak;

	atbm_memset(&efuse_d,0,sizeof(struct efuse_headr));
	atbm_memset(&efuse_bak,0,sizeof(struct efuse_headr));

	

	//tmp = DCXOCodeRead(hw_priv);printk("tmp %d\n"tmp);	
	if(ucWriteEfuseFlag)
	{
		wifi_printk(WIFI_DBG_ERROR, "ucWriteEfuseFlag :%d\n",ucWriteEfuseFlag);
		wsm_get_efuse_data(hw_priv,(void *)&efuse_d,sizeof(struct efuse_headr));
		
		if(efuse_d.version == 0)
		{
			//The first time efuse is written,all the data should be written, 
			//The production test only modifies part of the value, so efuse cannot be written.
			iResult = -3;
			goto FEEQ_ERR;
		}

		if(efuse_d.dcxo_trim == dcxo) // old dcxo equal new dcxo, no need to write efuse.
		{
			wifi_printk(WIFI_DBG_ERROR, " old dcxo equal new dcxo, no need to write efuse.\n");
			iResult = 0;
			goto FEEQ_ERR;
		}
		efuse_d.dcxo_trim = dcxo;
		/*
		*LMC_STATUS_CODE__EFUSE_VERSION_CHANGE	failed because efuse version change  
		*LMC_STATUS_CODE__EFUSE_FIRST_WRITE, 		failed because efuse by first write   
		*LMC_STATUS_CODE__EFUSE_PARSE_FAILED,		failed because efuse data wrong, cannot be parase
		*LMC_STATUS_CODE__EFUSE_FULL,				failed because efuse have be writen full
		*/
		ret = wsm_efuse_change_data_cmd(hw_priv, &efuse_d,0);
		if (ret == LMC_STATUS_CODE__EFUSE_FIRST_WRITE)
		{
			iResult = -3;
		}else if (ret == LMC_STATUS_CODE__EFUSE_PARSE_FAILED)
		{
			iResult = -4;
		}else if (ret == LMC_STATUS_CODE__EFUSE_FULL)
		{
			iResult = -5;
		}else if (ret == LMC_STATUS_CODE__EFUSE_VERSION_CHANGE)
		{
			iResult = -6;
		}else
		{
			iResult = 0;
		}
		
		frame_hexdump("efuse_d", (atbm_uint8 *)&efuse_d, sizeof(struct efuse_headr));
		wsm_get_efuse_data(hw_priv,(void *)&efuse_bak, sizeof(struct efuse_headr));
		frame_hexdump("efuse_bak", (atbm_uint8 *)&efuse_bak, sizeof(struct efuse_headr));
		
		if(atbm_memcmp((void *)&efuse_bak,(void *)&efuse_d, sizeof(struct efuse_headr)) !=0)
		{
			iResult = -2;
		}else
		{
			iResult = 0;
		}
		
	}

	
FEEQ_ERR:	
	
	/*sprintf(buff, "cfo:%d,evm:%d,gainImb:%d, phaseImb:%d,dcxo:%d,result:%d (0:OK; -1:FreqOffset Error; -2:efuse hard error;"
		" -3:efuse no written; -4:efuse anaysis failed; -5:efuse full; -6:efuse version change)",
	rxs_s.Cfo,
	rxs_s.evm,
	rxs_s.GainImb,
	rxs_s.PhaseImb,
	dcxo,
	iResult
	);*/

	//if((ret = copy_to_user(wrqu->data.pointer, buff, strlen(buff))) != 0){
	//	return -EINVAL;
	//}

	return iResult;
}

/**************************************************************************
**
** NAME         LMC_FM_GetATBMIe
**
** PARAMETERS:  pElements  -> Pointer to the Ie list
**              Length     -> Size of the Ie List
**              
** RETURNS:     Pointer to element if found or 0 otherwise.
**
** DESCRIPTION  Searches for ATBM test element  from a given IE list.
** 
**************************************************************************/
atbm_uint8* LMC_FM_GetATBMIe(atbm_uint8 *pElements,atbm_uint16 Length)
{
  atbm_uint8     ATBMIeOui[3]   = ATBM_OUI	;
  
  struct ATBM_TEST_IE  *Atbm_Ie;
	//dump_mem(pElements,Length);

   if(Length > sizeof(struct ATBM_TEST_IE)){
		pElements += Length-sizeof(struct ATBM_TEST_IE);
		Atbm_Ie =(struct ATBM_TEST_IE  *) pElements;
		
		/*wifi_printk(WIFI_DBG_ERROR, "Atbm_Ie->oui_type %x,Atbm_Ie->oui %x %x,size %x\n",
			Atbm_Ie->oui_type,
			Atbm_Ie->oui[2],
			ATBMIeOui[2],
			sizeof(struct ATBM_TEST_IE));
		
		dump_mem(pElements,16);*/

		 if(pElements[0]== D11_WIFI_ELT_ID){
			 if((memcmp(Atbm_Ie->oui,ATBMIeOui,3)==0)&&
			 	(Atbm_Ie->oui_type== WIFI_ATBM_IE_OUI_TYPE) ){
				return pElements;
			}
		 }
   }

  return (atbm_uint8 *)NULL  ;
}//end LMC_FM_GetP2PIe()

int etf_v2_compare_test_result(void)
{	
	if((gthreshold_param.txpwrmax == 0) && (gthreshold_param.txpwrmin == 0))
	{
		gthreshold_param.txpwrmax = 65536;
		if((efuse_data_etf.specific & 0x1))//outerPA(6038)
		{
			gthreshold_param.txpwrmin = -60+gthreshold_param.cableloss;	
			wifi_printk(WIFI_DBG_ERROR,"Use txpwrmin threshold[-60+30]:%d\n", gthreshold_param.txpwrmin);
		}
		else
		{
			gthreshold_param.txpwrmin = -84+gthreshold_param.cableloss;	
			wifi_printk(WIFI_DBG_ERROR,"Use txpwrmin threshold[-84+30]:%d\n", gthreshold_param.txpwrmin);
		}
	}

	if((gthreshold_param.txevmthreshold != 0) && (gRxs_s.txevm > gthreshold_param.txevmthreshold))
	{
		wifi_printk(WIFI_DBG_ERROR,"Test txevm:%d > threshold txevm:%d\n", gRxs_s.txevm, gthreshold_param.txevmthreshold);
		return 1;
	}

	if((gthreshold_param.rxevmthreshold != 0) && (gRxs_s.evm > gthreshold_param.rxevmthreshold))
	{
		wifi_printk(WIFI_DBG_ERROR,"Test rxevm:%d > threshold rxevm:%d\n", gRxs_s.evm, gthreshold_param.rxevmthreshold);
		return 2;
	}
	if((gthreshold_param.txpwrmax != 0) && (gthreshold_param.txpwrmin != 0) &&
		((gRxs_s.TxRSSI > gthreshold_param.txpwrmax) ||
		(gRxs_s.TxRSSI < gthreshold_param.txpwrmin)))
	{
		wifi_printk(WIFI_DBG_ERROR,"Test txpower:%d,txpowermax:%d, txpowermin:%d\n",
			gRxs_s.TxRSSI, gthreshold_param.txpwrmax, gthreshold_param.txpwrmin);
		return 3;
	}
	if((gthreshold_param.rxpwrmax != 0) && (gthreshold_param.rxpwrmin!= 0) &&
		((gRxs_s.RxRSSI > gthreshold_param.rxpwrmax) ||
		(gRxs_s.RxRSSI < gthreshold_param.rxpwrmin)))
	{
		wifi_printk(WIFI_DBG_ERROR,"Test rxpower:%d,rxpowermax:%d, rxpowermin:%d\n",
			gRxs_s.RxRSSI, gthreshold_param.rxpwrmax, gthreshold_param.rxpwrmin);
		return 4;
	}

	return 0;
}

void etf_v2_scan_end(struct atbmwifi_common *hw_priv, struct atbmwifi_vif *vif )
{
	int result = 0;//(0:OK; -1:FreqOffset Error; -2:Write efuse Failed;-3:efuse not write;-4:rx fail)
	atbm_uint32 dcxo = 0;
	int freqErrorHz;
	int ErrCode = -1;

	etf_rx_status_get(hw_priv);
	atbm_SleepMs(10);

	if(atbm_test_rx_cnt <= 5){
		memset(&gRxs_s, 0, sizeof(struct rxstatus_signed));
#if CONFIG_ATBM_PRODUCT_TEST_USE_GOLDEN_LED
		if((Atbm_Test_Success == 1) || (Atbm_Test_Success == -1)){
			gRxs_s.valid = 1;	
			Atbm_Test_Success = 0;
			atbm_test_rx_cnt = 0;
			txevm_total = 0;
			ETF_bStartTx = 0;
			return;
		}
#endif
		wifi_printk(WIFI_DBG_ERROR, "etf rx data[%d] less than 5 packet\n",atbm_test_rx_cnt);
		gRxs_s.result = -7;		

		gRxs_s.dcxo = dcxo;
		gRxs_s.valid = 1;	
		atbm_test_rx_cnt = 0;
		txevm_total = 0;
		ETF_bStartTx = 0;
		goto end;
	}
	
	gRxs_s.TxRSSI += gthreshold_param.cableloss;
	gRxs_s.txevm = txevm_total/atbm_test_rx_cnt;
	
	wifi_printk(WIFI_DBG_ERROR, "Average: Cfo:%d,TxRSSI:%d,RxRSSI:%d,txevm:%d,rxevm:%d\n",	
	gRxs_s.Cfo,
	gRxs_s.TxRSSI,
	gRxs_s.RxRSSI,
	gRxs_s.txevm,
	gRxs_s.evm
	);
	
#if 0//CONFIG_ATBM_PRODUCT_TEST_NO_UART
	int efuse_remainbit = 0;

	efuse_remainbit = wsm_get_efuse_status(hw_priv, vif);
	printk("efuse remain bit:%d\n", efuse_remainbit);

	if(efuse_remainbit < 8)
	{		
		printk("##efuse is full,do not calibrte FreqOffset\n##");
		dcxo = efuse_data_etf.dcxo_trim;
		if(gthreshold_param.freq_ppm != 0)
		{
			if((gRxs_s.Cfo > -gthreshold_param.freq_ppm) &&
				(gRxs_s.Cfo < gthreshold_param.freq_ppm))
			{
				printk("#1#cur cfo:%d, targetFreqOffset:%d\n",
					gRxs_s.Cfo, gthreshold_param.freq_ppm);
				goto success;
			}
			else
			{
				printk("#1#cur cfo:%d, targetFreqOffset:%d\n",
					gRxs_s.Cfo, gthreshold_param.freq_ppm);
				goto Error;
			}
		}
		else
		{
			if((gRxs_s.Cfo > -TARGET_FREQOFFSET_HZ) &&
				(gRxs_s.Cfo < TARGET_FREQOFFSET_HZ))
			{
				printk("#2#cur cfo:%d, targetFreqOffset:%d\n",
					gRxs_s.Cfo, TARGET_FREQOFFSET_HZ);
				goto success;
			}
			else
			{
				printk("#2#cur cfo:%d, targetFreqOffset:%d\n",
					gRxs_s.Cfo, TARGET_FREQOFFSET_HZ);
				goto Error;
			}
		}
	}
#endif
	if(gthreshold_param.freq_ppm != 0)
		result = Test_FreqOffset_v2(hw_priv,&dcxo,&freqErrorHz);
	else
	{
		dcxo = efuse_data_etf.dcxo_trim;
		wifi_printk(WIFI_DBG_ERROR, "Not need to Calibrate FreqOffset\n");
		result = 0;
		goto success;
	}
	
	if(result == 1)
	{
		//start next scan
		wifi_printk(WIFI_DBG_ERROR, "start next scan\n");

		//mutex_lock(&hw_priv->conf_mutex);
		//wsm_stop_tx(hw_priv);
		//mutex_unlock(&hw_priv->conf_mutex);

		atbm_SleepMs(100);
		txevm_total = 0;
		atbm_test_rx_cnt = 0;
		wsm_start_tx_v2(hw_priv,vif);
	}
	else  if(result == 0)  //etf dcxo success
	{
success:
		if((ErrCode = etf_v2_compare_test_result()) != 0)
			goto Error;
		wifi_printk(WIFI_DBG_ERROR, "etf test success \n");
		gRxs_s.result = atbm_freqoffset_save_efuse(hw_priv,gRxs_s,dcxo);

		gRxs_s.dcxo = dcxo;
		gRxs_s.valid = 1;
		//del_timer_sync(&hw_priv->etf_expire_timer);
#if CONFIG_ATBM_PRODUCT_TEST_USE_GOLDEN_LED
		Atbm_Test_Success = 1;
		//wsm_send_result(hw_priv,vif);
		wsm_start_tx_v2(hw_priv,vif);
#endif
		
	}else
	{
		gRxs_s.result = -1;
Error:
		gRxs_s.result = ErrCode;
		gRxs_s.dcxo = dcxo;
		gRxs_s.valid = 1;
		wifi_printk(WIFI_DBG_ERROR, "etf test Fail \n");
		//del_timer_sync(&hw_priv->etf_expire_timer);
#if CONFIG_ATBM_PRODUCT_TEST_USE_GOLDEN_LED
		Atbm_Test_Success = -1;
		//wsm_send_result(hw_priv,vif);
		wsm_start_tx_v2(hw_priv,vif);
#endif

	}
end:
	if(gRxs_s.valid)
		atbm_etf_PT_Test_result_get();
	txevm_total = 0;
	g_ProductTestGlobal = 0;
	atbm_test_rx_cnt = 0;
	ETF_bStartTx = 0;
}

void etf_v2_scan_rx(struct atbmwifi_common *hw_priv,struct atbm_buff *skb,atbm_uint8 rssi )
{

	atbm_int32 Cfo;
	atbm_int32  RSSI;
	atbm_int32 tmp;
	atbm_int16 txevm;
	struct ATBM_TEST_IE  *Atbm_Ie = NULL;	
	atbm_uint8 *data = (atbm_uint8 *)skb->abuf + offsetof(struct atbmwifi_ieee80211_mgmt, u.probe_resp.variable);
	int len = skb->dlen - offsetof(struct atbmwifi_ieee80211_mgmt, u.probe_resp.variable);
	Atbm_Ie = (struct ATBM_TEST_IE  *)LMC_FM_GetATBMIe(data,len);
	
#if CONFIG_ATBM_PRODUCT_TEST_USE_GOLDEN_LED
	if((Atbm_Test_Success == 1) || (Atbm_Test_Success == -1))
	{
		return;
	}
#endif

	if((Atbm_Ie) && (Atbm_Ie->featureid == gthreshold_param.featureid))
	{
		tmp				= Atbm_Ie->result[1];
		tmp				= (atbm_int32)N_BIT_TO_SIGNED_32BIT(tmp, 16);
		Cfo = (atbm_int32)(((tmp*12207)/10));
		 
		txevm				= (atbm_int16)N_BIT_TO_SIGNED_32BIT(Atbm_Ie->result[2], 16);
		RSSI			= (atbm_int16)N_BIT_TO_SIGNED_32BIT(Atbm_Ie->result[3], 10);
		
		if( RSSI < gthreshold_param.rssifilter)
		{
			wifi_printk(WIFI_DBG_ERROR, "[%d]: Cfo:%d,TxRSSI:%d, rx dump packet,throw......\n",
			atbm_test_rx_cnt,	
			Cfo,
			RSSI
			);
			return;
		}

		if(txevm < gthreshold_param.txevm)
		{
			if(atbm_test_rx_cnt == 0)
			{		
				gRxs_s.Cfo = Cfo;
				//gRxs_s.evm = evm;
				gRxs_s.TxRSSI = RSSI;
			}else
			{

				gRxs_s.Cfo = (gRxs_s.Cfo*3 + Cfo )/4;
				//gRxs_s.evm = evm;
				gRxs_s.TxRSSI = RSSI;
				//gRxs_s.TxRSSI = (gRxs_s.TxRSSI*3*10 + RSSI*10 +5)/40;

			}

			wifi_printk(WIFI_DBG_ERROR, "[%d]: Cfo1:%d, Cfo:%d,TxRSSI:%d,txevm:%d\n",
			atbm_test_rx_cnt,
			tmp,
			Cfo,
			RSSI,txevm
			);

			//printk("etf_v2_scan_rx %d,cnt %d,[0x%x,0x%x,0x%x,0x%x,0x%x]\n",Atbm_Ie->test_type,atbm_test_rx_cnt,
			//	Atbm_Ie->result[0],Atbm_Ie->result[1],Atbm_Ie->result[2],Atbm_Ie->result[3],Atbm_Ie->result[3]);
			txevm_total += txevm;
			atbm_test_rx_cnt++;
		}
		
	}
	else
	{
		wifi_printk(WIFI_DBG_ERROR,"<<< Not Found atbm_ie >>>\n");
	}

}


